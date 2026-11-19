package webhookrx

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/notify/sinks"
)

func TestVerify_StandardWebhooksVector(t *testing.T) {
	const sec = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	id, ts, body := "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`)
	good := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	now := time.Unix(1614265330, 0)
	require.NoError(t, Verify(sec, id, ts, body, good, now))
	require.NoError(t, Verify(sec, id, ts, body, "v1,Zm9v "+good, now)) // any listed signature may match
	require.Error(t, Verify(sec, id, ts, []byte(`{"test": 1}`), good, now))
	require.Error(t, Verify(sec, id, ts, body, good, now.Add(10*time.Minute))) // outside tolerance
	require.Error(t, Verify(sec, id, ts, body, "v2,"+good[3:], now))
}

func TestReceiver_RecordsTypeAndVerification(t *testing.T) {
	const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" //nolint:gosec // G101: the published Standard Webhooks test key
	const typ = "au.theitdept.ffs.digest.v1"
	body := []byte(`{"specversion":"1.0","id":"msg_1","source":"/ffs/e2e","type":"` + typ + `","data":{"kind":"digest"}}`)
	rx := New(secret)

	post := func(id, sig string) int {
		t.Helper()
		now := time.Now()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("webhook-id", id)
		req.Header.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
		if sig == "" { // signed by the product's webhook sink
			var err error
			sig, err = sinks.Sign(secret, id, now, body)
			require.NoError(t, err)
		}
		req.Header.Set("webhook-signature", sig)
		w := httptest.NewRecorder()
		rx.ServeHTTP(w, req)
		return w.Code
	}

	require.Equal(t, http.StatusNoContent, post("msg_1", ""))
	got := rx.Deliveries()
	require.Len(t, got, 1)
	require.Equal(t, typ, got[0].Type)
	require.Equal(t, "msg_1", got[0].ID)
	require.True(t, got[0].Verified)
	require.Equal(t, body, got[0].Body)

	require.Equal(t, http.StatusUnauthorized, post("msg_2", "v1,Zm9v"))
	got = rx.Deliveries()
	require.Len(t, got, 2)
	require.Equal(t, typ, got[1].Type)
	require.False(t, got[1].Verified)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	d, err := rx.Wait(ctx, func(d Delivery) bool { return !d.Verified })
	require.NoError(t, err)
	require.Equal(t, "msg_2", d.ID)
	_, err = rx.Wait(ctx, func(d Delivery) bool { return d.ID == "msg_3" })
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
