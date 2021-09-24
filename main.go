package main

import (
	"bufio"
	"bytes"
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
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/gofrs/flock"
	shell "github.com/ipfs/go-ipfs-api"
	files "github.com/ipfs/go-ipfs-files"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"go.uber.org/multierr"
)

var (
	GoProxy       = "direct"
	GoModCache    = filepath.Join(build.Default.GOPATH, "pkg", "mod", "cache")
	GoModDownload = filepath.Join(GoModCache, "download")
	Gateway       = "http://127.0.0.1:8080"
	DepsFile      = "go.ipfs"
	GoCommand     = "go"
)

func init() {
	// Fixup the path if we're running as "go"
	if filepath.Base(os.Args[0]) == "go" {
		path := os.Getenv("PATH")
		if path == "" {
			fmt.Fprintln(os.Stderr, "failed to find go command: no PATH set")
			os.Exit(2)
		}

		ipgoPath, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to locate ipgo: %s\n", err)
			os.Exit(2)
		}

		ipgoDir := filepath.Dir(ipgoPath)

		splitPath := filepath.SplitList(path)
		newPath := splitPath[:0]
		for _, p := range splitPath {
			if abs, err := filepath.Abs(p); err != nil || abs == ipgoDir {
				continue
			}
			newPath = append(newPath, p)
		}

		os.Setenv("PATH", strings.Join(newPath, string(filepath.ListSeparator)))
	}

	res, err := exec.Command(GoCommand, "env", "GOMODCACHE", "GOPROXY").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to read 'go env': %s\n", err)
		return
	}
	lines := strings.Split(string(res), "\n")
	if len(lines) != 3 {
		fmt.Fprintln(os.Stderr, "ERROR: failed to parse 'go env' results:")
		os.Stderr.Write(res)
		return
	}
	if lines[0] != "" {
		GoModCache = filepath.Join(lines[0], "cache")
		GoModDownload = filepath.Join(GoModCache, "download")
	}
	if lines[1] != "" {
		GoProxy = lines[1]
	}
}

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

func (m *IpfsMod) getArtifacts() (results []artifact, err error) {
	pkgs, err := m.getPackages()
	if err != nil {
		return nil, err
	}
	// TODO: Remove this. See https://github.com/golang/go/issues/29772
	meta, err := m.getMetadata()
	if err != nil {
		return nil, err
	}
	return append(pkgs, meta...), nil
}

func (m *IpfsMod) getPackages() (results []artifact, err error) {
	cmd := m.Command("mod", "download", "-json")
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

func (m *IpfsMod) getMetadata() (results []artifact, err error) {
	cmd := m.Command("mod", "graph")
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

type lazyFileReader struct {
	openOnce sync.Once
	path     string

	fi  *os.File
	err error
}

func newLazyFileReader(path string) *lazyFileReader {
	return &lazyFileReader{path: path}
}

func (l *lazyFileReader) Read(buf []byte) (int, error) {
	l.openOnce.Do(func() {
		l.fi, l.err = os.Open(l.path)
	})
	if l.err != nil {
		return 0, l.err
	}
	return l.fi.Read(buf)
}

func (l *lazyFileReader) Close() error {
	l.openOnce.Do(func() {})
	if l.fi != nil {
		return l.fi.Close()
	}
	return l.err
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

			if !dir.add(relativeArtifact(p), newLazyFileReader(p)) {
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

type IpfsMod struct {
	Path string `json:"path"`
	Hash string `json:"checksum"`
}

func Load() (*IpfsMod, error) {
	// Default to "empty".
	var lock IpfsMod

	depsBytes, err := ioutil.ReadFile(DepsFile)
	if os.IsNotExist(err) {
		return &lock, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read %q: %s", DepsFile, err)
	} else if len(depsBytes) == 0 {
		// We allow this file to be empty before init.
		return &lock, nil
	} else if err := json.Unmarshal(depsBytes, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse %q: %s", DepsFile, err)
	}
	return &lock, nil
}

func (m *IpfsMod) Command(args ...string) *exec.Cmd {
	cmd := exec.Command(GoCommand, args...)
	if m.Path != "" {
		cmd.Env = append(os.Environ(),
			"GO111MODULE=on",
			"GOPROXY="+Gateway+m.Path+","+GoProxy,
		)
	}
	return cmd
}

func (m *IpfsMod) Run(args ...string) error {
	cmd := m.Command(args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func (m *IpfsMod) goSumFile() (*os.File, error) {
	modInfo, err := exec.Command(GoCommand, "list", "-m", "-json").Output()
	if err != nil {
		return nil, err
	}
	var info struct{ Dir string }
	if err := json.Unmarshal(modInfo, &info); err != nil {
		return nil, err
	}
	if info.Dir == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Join(info.Dir, "go.sum"))
	if os.IsNotExist(err) {
		err = nil
	}
	return f, err
}

func (m *IpfsMod) checkHash(file io.Reader) (bool, error) {
	if m.Hash == "" {
		return false, nil
	}

	_, decoded, err := multibase.Decode(m.Hash)
	if err != nil {
		return false, err
	}
	info, err := multihash.Decode(decoded)
	if err != nil {
		return false, err
	}

	if mh, err := multihash.SumStream(file, info.Code, info.Length); err != nil {
		return false, err
	} else {
		return bytes.Equal(mh, decoded), nil
	}
}

func (m *IpfsMod) Update() error {
	// Check the gosum file.
	goSumFile, err := m.goSumFile()
	if err != nil {
		return err
	} else if goSumFile == nil {
		// If it doesn't exist, there's nothing to update.
		return nil
	}

	defer goSumFile.Close()

	lock := flock.New(DepsFile)

	// Now take the write lock so we don't conflict with other updates.
	lock.Lock()
	defer lock.Unlock()

	// If the hash is the same, there's nothing to do.
	same, err := m.checkHash(goSumFile)
	if same || err != nil {
		return err
	}

	// Ok, something has changed.

	s := shell.NewLocalShell()
	if s == nil {
		// TODO: Public instance?
		return fmt.Errorf("can't connect to local IPFS instance")
	}

	artifacts, err := m.getArtifacts()
	if err != nil {
		return err
	}

	dir, err := artifactsToDirectory(artifacts)
	if err != nil {
		return err
	}

	finalHash, err := ipfsAdd(
		s,
		files.NewSliceDirectory([]files.DirEntry{
			files.FileEntry("files", dir),
		}),
	)
	if err != nil {
		return err
	}

	// Re-hash the sum file as it may have changed.
	if _, err := goSumFile.Seek(0, os.SEEK_SET); err != nil {
		return err
	}
	if hash, err := multihash.SumStream(goSumFile, multihash.SHA2_256, -1); err != nil {
		return err
	} else if hash, err := multibase.Encode(multibase.Base32, hash); err != nil {
		return err
	} else {
		m.Hash = hash
	}
	m.Path = "/ipfs/" + finalHash

	if fi, err := os.Create(DepsFile); err != nil {
		return err
	} else if err := json.NewEncoder(fi).Encode(m); err != nil {
		_ = fi.Close()
		return err
	} else {
		return fi.Close()
	}
}

func run() error {
	args := os.Args[1:]
	mod, err := Load()
	if err != nil {
		return err
	}
	return multierr.Combine(mod.Run(args...), mod.Update())
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
