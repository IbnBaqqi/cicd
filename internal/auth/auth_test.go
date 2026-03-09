package auth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	type test struct {
		name string
		input http.Header
		result string
		wantErr bool
	}
	
	header := http.Header{}
	header.Set("Authorization", "")
	header2 := http.Header{}
	header2.Set("Authorization", "ApiKey 01234")

	tests := []test{
		{
			name: "no auth header",
			input: header,
			result: "",
			wantErr: true,
		},
		{
			name: "valid api key",
			input: header2,
			result: "01234",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		res, err := GetAPIKey(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("expected error: %v, got: %v", tc.wantErr, err)
		}
		if res != tc.result {
			t.Fatalf("expected result: %v, got: %v", tc.result, res)
		}
	}
}

func TestGetAPIKey2(t *testing.T) {
	tests := []struct {
		key       string
		value     string
		expect    string
		expectErr string
	}{
		{
			expectErr: "no authorization header",
		},
		{
			key:       "Authorization",
			expectErr: "no authorization header",
		},
		{
			key:       "Authorization",
			value:     "-",
			expectErr: "malformed authorization header",
		},
		{
			key:       "Authorization",
			value:     "Bearer xxxxxx",
			expectErr: "malformed authorization header",
		},
		{
			key:       "Authorization",
			value:     "ApiKey xxxxxx",
			expect:    "xxxxxx",
			expectErr: "not expecting an error",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("TestGetAPIKey Case #%v:", i), func(t *testing.T) {
			header := http.Header{}
			header.Add(test.key, test.value)

			output, err := GetAPIKey(header)
			if err != nil {
				if strings.Contains(err.Error(), test.expectErr) {
					return
				}
				t.Errorf("Unexpected: TestGetAPIKey:%v\n", err)
				return
			}

			if output != test.expect {
				t.Errorf("Unexpected: TestGetAPIKey:%s", output)
				return
			}
		})
	}
}