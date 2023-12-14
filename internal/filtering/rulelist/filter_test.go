package rulelist_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilter_Refresh(t *testing.T) {
	cacheDir := t.TempDir()
	uid := rulelist.MustNewFilterUID()

	initialFile := filepath.Join(cacheDir, "initial.txt")
	initialData := []byte(
		testRuleTextTitle +
			testRuleTextBlocked,
	)
	urlParseErr := os.WriteFile(initialFile, initialData, 0o644)
	require.NoError(t, urlParseErr)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := io.WriteString(w, testRuleTextTitle+testRuleTextBlocked)
		require.NoError(pt, err)
	}))

	srvURL, urlParseErr := url.Parse(srv.URL)
	require.NoError(t, urlParseErr)

	testCases := []struct {
		url           *url.URL
		name          string
		wantNewErrMsg string
	}{{
		url:           nil,
		name:          "nil_url",
		wantNewErrMsg: "no url",
	}, {
		url: &url.URL{
			Scheme: "ftp",
		},
		name:          "bad_scheme",
		wantNewErrMsg: `bad url scheme: "ftp"`,
	}, {
		name: "file",
		url: &url.URL{
			Scheme: "file",
			Path:   initialFile,
		},
		wantNewErrMsg: "",
	}, {
		name:          "http",
		url:           srvURL,
		wantNewErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := rulelist.NewFilter(&rulelist.FilterConfig{
				URL:         tc.url,
				Name:        tc.name,
				UID:         uid,
				URLFilterID: testURLFilterID,
				Enabled:     true,
			})
			testutil.AssertErrorMsg(t, tc.wantNewErrMsg, err)
			if tc.wantNewErrMsg != "" {
				return
			}

			require.NotNil(t, f)

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			t.Cleanup(cancel)

			buf := make([]byte, rulelist.DefaultRuleBufSize)
			cli := &http.Client{
				Timeout: testTimeout,
			}

			res, err := f.Refresh(ctx, buf, cli, cacheDir, rulelist.DefaultMaxRuleListSize)
			require.NoError(t, err)

			assert.Equal(t, testTitle, res.Title)
			assert.Equal(t, len(testRuleTextBlocked), res.BytesWritten)
			assert.Equal(t, 1, res.RulesCount)

			// Check that the cached file exists.
			_, err = os.Stat(filepath.Join(cacheDir, uid.String()+".txt"))
			require.NoError(t, err)

			err = f.Close()
			require.NoError(t, err)
		})
	}
}
