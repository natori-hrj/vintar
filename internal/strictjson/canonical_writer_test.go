package strictjson

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCanonicalizeTo(t *testing.T) {
	body := strings.Repeat("a", 4082) + strings.Repeat("\u2028😀", 1000)
	input := `{"𐀀":1,"\ue000":1.0,"\udfff":-0.0,"a":"` + body + `","n":1e15}`
	want := `{"a":"` + strings.Repeat("a", 4082) + strings.Repeat(`\u2028\ud83d\ude00`, 1000) +
		`","n":1000000000000000.0,"\udfff":-0.0,"\ue000":1.0,"\ud800\udc00":1}`
	var dst bytes.Buffer
	if err := CanonicalizeTo(&dst, []byte(input)); err != nil || dst.String() != want {
		t.Fatalf("canonical bytes differ: size=%d, want=%d, err=%v", dst.Len(), len(want), err)
	}
	for _, tc := range []struct {
		w    io.Writer
		want error
	}{
		{failingWriter{nil}, io.ErrShortWrite},
		{failingWriter{io.ErrClosedPipe}, io.ErrClosedPipe},
	} {
		if err := CanonicalizeTo(tc.w, []byte(input)); !errors.Is(err, tc.want) {
			t.Errorf("got %v, want %v", err, tc.want)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
