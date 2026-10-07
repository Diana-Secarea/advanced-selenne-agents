package tetragon

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Position is where reading stopped: the start of the first line not yet
// handed out. Saved to disk, it lets a restarted sensor carry on exactly
// there — in the same file even after Tetragon rotated it (found by inode).
type Position struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Tailer follows Tetragon's export file. Tetragon rotates it by renaming it
// to <name>-<timestamp>.<ext> and starting a new file; the tailer drains the
// renamed file to its end before moving to the new one, so no line is lost.
type Tailer struct {
	path    string
	f       *os.File
	inode   uint64
	r       *bufio.Reader
	offset  int64  // start of the next unread line
	partial []byte // a line Tetragon has not finished writing yet
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// OpenTailer starts at pos, or at the beginning of path for a zero Position.
// A missing file is fine: the tailer waits for Tetragon to create it.
func OpenTailer(path string, pos Position) (*Tailer, error) {
	t := &Tailer{path: path}
	if pos.Inode != 0 {
		if cur, err := os.Stat(path); err == nil && inodeOf(cur) == pos.Inode {
			return t, t.open(path, pos.Offset)
		}
		// rotated while we were down: finish the old file first
		if old := findByInode(path, pos.Inode); old != "" {
			return t, t.open(old, pos.Offset)
		}
	}
	err := t.open(path, 0)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	return t, err
}

func (t *Tailer) open(name string, offset int64) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if offset > fi.Size() { // truncated or replaced: start over
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	if t.f != nil {
		t.f.Close()
	}
	t.f, t.inode, t.offset, t.partial = f, inodeOf(fi), offset, nil
	t.r = bufio.NewReaderSize(f, 256*1024)
	return nil
}

// Next returns the next complete line and its offset. ok is false when
// there is nothing more for now; call again later.
func (t *Tailer) Next() (line []byte, offset int64, ok bool, err error) {
	if t.f == nil {
		if err := t.open(t.path, 0); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, 0, false, nil
			}
			return nil, 0, false, err
		}
	}
	for {
		chunk, err := t.r.ReadBytes('\n')
		if len(chunk) > 0 {
			t.partial = append(t.partial, chunk...)
		}
		if err == nil {
			line = bytes.TrimRight(t.partial, "\r\n")
			offset = t.offset
			t.offset += int64(len(t.partial))
			t.partial = nil
			if len(line) == 0 {
				continue
			}
			return line, offset, true, nil
		}
		if !errors.Is(err, io.EOF) {
			return nil, 0, false, err
		}
		// At the end of what has been written. Has Tetragon moved on?
		switched, err := t.followRotation()
		if err != nil || !switched {
			return nil, 0, false, err
		}
	}
}

// followRotation switches to the new file when the one being read was
// renamed away (or truncated in place) and has been read to its end.
func (t *Tailer) followRotation() (bool, error) {
	cur, err := os.Stat(t.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if inodeOf(cur) != t.inode {
		if len(t.partial) > 0 { // the old file ended mid-line: keep what it had
			t.partial = nil
		}
		err := t.open(t.path, 0)
		return err == nil, err
	}
	if cur.Size() < t.offset { // same file, truncated
		err := t.open(t.path, 0)
		return err == nil, err
	}
	return false, nil
}

func (t *Tailer) Position() Position {
	name := t.path
	if t.f != nil {
		name = t.f.Name()
	}
	return Position{Path: name, Inode: t.inode, Offset: t.offset}
}

func (t *Tailer) Close() error {
	if t.f == nil {
		return nil
	}
	return t.f.Close()
}

// Rotated lists Tetragon's rotated copies of path (<name>-<timestamp><ext>),
// oldest first — what a restart reads to rebuild its process table.
func Rotated(path string) []string {
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if n != base && strings.HasPrefix(n, stem+"-") && strings.HasSuffix(n, ext) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out) // the timestamp suffix sorts chronologically
	return out
}

func findByInode(path string, inode uint64) string {
	for _, name := range Rotated(path) {
		if fi, err := os.Stat(name); err == nil && inodeOf(fi) == inode {
			return name
		}
	}
	return ""
}

// ForEachLine calls fn for every complete line of name before offset `to`
// (-1: the whole file). Used to replay history into the process table.
func ForEachLine(name string, to int64, fn func([]byte)) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if to >= 0 {
		r = io.LimitReader(f, to)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 16*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			fn(sc.Bytes())
		}
	}
	return sc.Err()
}
