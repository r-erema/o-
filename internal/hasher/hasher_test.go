package hasher_test

import (
	"testing"

	"github.com/r-erema/paranoid/internal/hasher"
)

func Test_o(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name,
		input,
		secret,
		expect string
	}{
		{
			name:   "case 1",
			input:  "test_string",
			secret: "scrt",
			expect: "_NGQyMjI2MzdlODFi@",
		},
		{
			name:   "case 2",
			input:  "test_string2",
			secret: "scrt2",
			expect: "_MjFmM2I5MDNjMmI3@",
		},
	}
	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasher.Hash(tc.input, tc.secret); got != tc.expect {
				t.Errorf("o() = %v, want %v", got, tc.expect)
			}
		})
	}
}
