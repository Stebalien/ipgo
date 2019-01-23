package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"unicode"

	"github.com/ipfs/go-ipfs-api"
	"github.com/ipfs/go-ipfs-files"
)

var (
	GoModCache    = path.Join(build.Default.GOPATH, "pkg", "mod", "cache")
	GoModDownload = path.Join(GoModCache, "download")
	Gateway       = "http://127.0.0.1:8080"
	DepsFile      = "deps.ipfs"
	GoCommand     = "go"
)

func escapePath(s string) string {
	var builder strings.Builder
	builder.Grow(len(s))

	for _, r := range s {
		if unicode.IsUpper(r) {
			r = unicode.ToLower(r)
			builder.WriteByte('!')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

type artifact struct {
	Path    string
	Version string
	Info    string
	GoMod   string
	Zip     string
}

type download struct {
	artifact
	Error string
}

func getArtifacts() (results []artifact, err error) {
	pkgs, err := getPackages()
	if err != nil {
		return nil, err
	}
	// TODO: Remove this. See https://github.com/golang/go/issues/29772
	meta, err := getMetadata()
	if err != nil {
		return nil, err
	}
	return append(pkgs, meta...), nil
}

func getPackages() (results []artifact, err error) {
	cmd := exec.Command(GoCommand, "mod", "download", "-json")
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	defer func() {
		err2 := cmd.Wait()
		if err == nil {
			err = err2
		}
	}()

	decoder := json.NewDecoder(stdout)
	for {
		var result download
		switch err := decoder.Decode(&result); err {
		case nil:
		case io.EOF:
			return results, nil
		default:
			return nil, err
		}
		if result.Error != "" {
			return nil, errors.New(result.Error)
		}
		results = append(results, result.artifact)
	}
}

func getMetadata() (results []artifact, err error) {
	cmd := exec.Command(GoCommand, "mod", "graph")
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	defer func() {
		err2 := cmd.Wait()
		if err == nil {
			err = err2
		}
	}()

	lineScanner := bufio.NewScanner(stdout)
	for lineScanner.Scan() {
		line := lineScanner.Text()
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid 'go mod graph' output: %q", line)
		}
		dep := parts[1]
		verIdx := strings.LastIndexByte(dep, '@')
		if verIdx < 0 {
			return nil, fmt.Errorf("invalid 'go mod graph' output, missing version: %q", line)
		}
		var result artifact
		result.Path = dep[:verIdx]
		result.Version = dep[verIdx+1:]
		basePath := path.Join(GoModDownload, escapePath(result.Path), "@v", result.Version)
		result.GoMod = basePath + ".mod"
		result.Info = basePath + ".info"
		results = append(results, result)
	}
	return results, lineScanner.Err()
}

func relativeArtifact(s string) string {
	return strings.TrimLeft(strings.TrimPrefix(s, GoModDownload), "/")
}

type addResult struct {
	Hash string
}

type fileSet struct {
	files map[string]interface{}
}

func (f fileSet) add(p string, r io.Reader) bool {
	parts := strings.SplitN(p, "/", 2)
	name := parts[0]
	switch len(parts) {
	case 1:
		f.files[name] = r
	case 2:
		var dir fileSet
		switch dirent := f.files[name].(type) {
		case fileSet:
			dir = dirent
		case io.Reader:
			return false
		case nil:
			dir = newFileSet()
			f.files[name] = dir
		default:
			panic("wtf")
		}
		dir.add(parts[1], r)
	default:
		panic("wtf")
	}
	return true
}

func (f fileSet) toFile() files.Directory {
	dir := make([]files.DirEntry, 0, len(f.files))
	for n, e := range f.files {
		var fi files.Node
		switch e := e.(type) {
		case fileSet:
			fi = e.toFile()
		case io.Reader:
			fi = files.NewReaderFile(e)
		}
		dir = append(dir, files.FileEntry(n, fi))
	}
	return files.NewSliceDirectory(dir)
}
func (f fileSet) Close() error {
	for _, e := range f.files {
		if closer, ok := e.(io.Closer); ok {
			closer.Close()
		}
	}
	return nil
}

func newFileSet() fileSet {
	return fileSet{files: make(map[string]interface{})}
}

func artifactsToDirectory(artifacts []artifact) (files.Directory, error) {
	dir := newFileSet()
	added := make(map[string]struct{})
	for _, artifact := range artifacts {
		for _, p := range []string{artifact.Info, artifact.GoMod, artifact.Zip} {
			if p == "" {
				continue
			}
			if _, ok := added[p]; ok {
				continue
			}

			added[p] = struct{}{}

			file, err := os.Open(p)
			if err != nil {
				dir.Close()
				return nil, err
			}
			if !dir.add(relativeArtifact(p), file) {
				dir.Close()
				return nil, fmt.Errorf("BUG: file conflict at %q", p)
			}
		}

		// metadata only
		if artifact.Zip == "" {
			continue
		}

		if !dir.add(
			path.Join(path.Dir(relativeArtifact(artifact.Info)), "list"),
			strings.NewReader(artifact.Version+"\n"),
		) {
			dir.Close()
			return nil, fmt.Errorf("BUG: file conflict for version file")
		}
	}
	return dir.toFile(), nil
}

func ipfsAdd(s *shell.Shell, dir files.Directory) (string, error) {
	resp, err := s.Request("add").
		Option("recursive", true).
		Option("quieter", true).
		Option("hidden", true).
		Option("raw-leaves", true).
		Option("inline", true).
		Option("cid-version", 1).
		Body(files.NewMultiFileReader(dir, true)).
		Send(context.Background())
	if err != nil {
		return "", err
	}
	defer resp.Close()
	if resp.Error != nil {
		return "", resp.Error
	}
	dec := json.NewDecoder(resp.Output)
	var final string
	for {
		var out addResult
		err = dec.Decode(&out)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		final = out.Hash
	}
	return final, nil
}

func runGo(args ...string) error {
	depPathBytes, err := ioutil.ReadFile(DepsFile)
	cmd := exec.Command(GoCommand, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err == nil {
		depPath := strings.Trim(string(depPathBytes), " \n\r\t")
		cmd.Env = append(os.Environ(), "GO111MODULE=on", "GOPROXY="+Gateway+string(depPath))
	} else if os.IsNotExist(err) {
		// skip.
	} else {
		return fmt.Errorf("failed to read 'ipfs.deps': %s", err)
	}
	return cmd.Run()
}

// IpfsImport imports the package's dependencies into IPFS.
func IpfsImport() (string, error) {
	s := shell.NewLocalShell()
	if s == nil {
		// TODO: Public instance?
		return "", fmt.Errorf("can't connect to local IPFS instance")
	}

	artifacts, err := getArtifacts()
	if err != nil {
		return "", err
	}

	dir, err := artifactsToDirectory(artifacts)
	if err != nil {
		return "", err
	}

	finalHash, err := ipfsAdd(
		s,
		files.NewSliceDirectory([]files.DirEntry{
			files.FileEntry("files", dir),
		}),
	)
	if err != nil {
		return "", err
	}
	depPath := "/ipfs/" + finalHash
	return depPath, nil
}

// UpdateDepsFile is a imports the deps into IPFS and then writes out the deps
// file.
func UpdateDepsFile() (string, error) {
	depPath, err := IpfsImport()
	if err != nil {
		return "", err
	}
	return depPath, ioutil.WriteFile(DepsFile, []byte(depPath), 0644)
}

func run() error {
	args := os.Args[1:]
	if len(args) == 2 && args[0] == "mod" && args[1] == "ipfs-lock" {
		depPath, err := UpdateDepsFile()
		if err != nil {
			return err
		}
		fmt.Printf("dependencies published to: %s\n", depPath)
		return nil
	}
	return runGo(args...)
}

func main() {
	err := run()
	if err == nil {
		os.Exit(0)
	}

	type exitStatus interface {
		ExitStatus() int
	}

	switch err := err.(type) {
	case *exec.ExitError:
		switch err := err.Sys().(type) {
		case exitStatus:
			os.Exit(err.ExitStatus())
		}
	}
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
