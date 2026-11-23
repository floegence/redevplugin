package externalsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxPackageReconnects = 7

var errRestartPackage = errors.New("server returned a full replacement")

type packageStream struct {
	ctx                    context.Context
	fetcher                *Fetcher
	url                    PackageURL
	body                   io.ReadCloser
	replacement            *http.Response
	validator              string
	received, total        int64
	attempts               int
	readErr                error
	progress, reconnecting func(int64, int64)
	touch                  func()
}

func (fetcher *Fetcher) stageRemotePackage(ctx context.Context, locator PackageURL, response *http.Response, owner string, limit, expected int64, progress, reconnecting func(int64, int64), touch func()) (StagedArtifact, error) {
	stream := &packageStream{ctx: ctx, fetcher: fetcher, url: locator, progress: progress, reconnecting: reconnecting, touch: touch}
	for {
		stream.body = response.Body
		stream.validator = strongEntityTag(response.Header)
		stream.received, stream.total = 0, max(response.ContentLength, expected, 0)
		stream.readErr = nil
		if err := packageEncoding(response); err != nil {
			_ = stream.body.Close()
			return StagedArtifact{}, err
		}
		if stream.total > limit {
			_ = stream.body.Close()
			return StagedArtifact{}, externalError(ErrorArtifactTooLarge, "fetch", locator.DisplayURL(), fmt.Errorf("content length exceeds limit"))
		}
		if expected > 0 && response.ContentLength > 0 && response.ContentLength != expected {
			_ = stream.body.Close()
			return StagedArtifact{}, externalError(ErrorStageIntegrity, "fetch", locator.DisplayURL(), fmt.Errorf("content length differs from release"))
		}
		touch()
		artifact, err := fetcher.stage.stageWithReservationForOwner(ctx, owner, stream, limit, stream.total)
		closeErr := stream.body.Close()
		if stream.replacement != nil {
			response = stream.replacement
			stream.replacement = nil
			if !errors.Is(err, errRestartPackage) || ctx.Err() != nil {
				_ = response.Body.Close()
				return StagedArtifact{}, errors.Join(err, ctx.Err())
			}
			if progress != nil {
				progress(0, max(expected, response.ContentLength, 0))
			}
			continue
		}
		if err != nil {
			return StagedArtifact{}, err
		}
		if closeErr != nil {
			return StagedArtifact{}, errors.Join(externalError(ErrorTransport, "fetch", locator.DisplayURL(), closeErr), fetcher.stage.Remove(artifact))
		}
		return artifact, nil
	}
}

func (stream *packageStream) Read(buffer []byte) (int, error) {
	for {
		if stream.readErr != nil {
			if stream.readErr == io.EOF || stream.validator == "" || stream.received == 0 || stream.total > 0 && stream.received >= stream.total {
				return 0, stream.readErr
			}
			if err := stream.reconnect(); err != nil {
				return 0, err
			}
			stream.readErr = nil
		}
		read, err := stream.body.Read(buffer)
		if stream.total > 0 && int64(read) > stream.total-stream.received {
			return 0, externalError(ErrorStageIntegrity, "fetch", stream.url.DisplayURL(), fmt.Errorf("body exceeds declared size"))
		}
		stream.received += int64(read)
		if err == io.EOF && stream.total > stream.received {
			if stream.validator == "" {
				return 0, externalError(ErrorStageIntegrity, "fetch", stream.url.DisplayURL(), fmt.Errorf("body ended before declared size"))
			}
			err = io.ErrUnexpectedEOF
		}
		stream.readErr = err
		if read > 0 {
			stream.touch()
			if stream.progress != nil {
				stream.progress(stream.received, stream.total)
			}
			return read, nil
		}
		if err == nil {
			return 0, nil
		}
	}
}

func (stream *packageStream) reconnect() error {
	if stream.ctx.Err() != nil {
		return stream.ctx.Err()
	}
	_ = stream.body.Close()
	stream.body = http.NoBody
	if stream.reconnecting != nil {
		stream.reconnecting(stream.received, stream.total)
	}
	lastErr := stream.readErr
	for stream.attempts < maxPackageReconnects {
		select {
		case <-stream.ctx.Done():
			return stream.ctx.Err()
		case <-time.After(500 * time.Millisecond << stream.attempts):
		}
		stream.attempts++
		response, err := stream.fetcher.fetchHop(stream.ctx, stream.url, stream.received, stream.validator)
		if err != nil {
			if CodeOf(err) == ErrorTransport || CodeOf(err) == ErrorDNS {
				lastErr = err
				continue
			}
			return err
		}
		switch response.StatusCode {
		case http.StatusOK:
			stream.replacement = response
			return errRestartPackage
		case http.StatusPartialContent:
			total, valid := remainingPackageRange(response, stream.received, stream.total, stream.validator)
			if !valid {
				_ = response.Body.Close()
				return externalError(ErrorStageIntegrity, "resume", stream.url.DisplayURL(), fmt.Errorf("partial response does not match requested bytes"))
			}
			if err := packageEncoding(response); err != nil {
				_ = response.Body.Close()
				return err
			}
			stream.body, stream.total = response.Body, total
			return nil
		default:
			_ = response.Body.Close()
			return externalHTTPError("resume", stream.url.DisplayURL(), response.StatusCode, parseRetryAfter(response.Header.Get("Retry-After"), time.Now()), fmt.Errorf("unexpected range response"))
		}
	}
	return lastErr
}

func remainingPackageRange(response *http.Response, offset, total int64, validator string) (int64, bool) {
	values := response.Header.Values("Content-Range")
	if len(values) != 1 || strongEntityTag(response.Header) != validator {
		return 0, false
	}
	_, sizeText, ok := strings.Cut(values[0], "/")
	size, err := strconv.ParseInt(sizeText, 10, 64)
	if !ok || err != nil || size <= offset || size > maxStreamBytes || total > 0 && total != size {
		return 0, false
	}
	return size, values[0] == fmt.Sprintf("bytes %d-%d/%d", offset, size-1, size) && (response.ContentLength < 0 || response.ContentLength == size-offset)
}

func strongEntityTag(headers http.Header) string {
	values := headers.Values("ETag")
	if len(values) != 1 {
		return ""
	}
	tag := values[0]
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return ""
	}
	for index := 1; index < len(tag)-1; index++ {
		if tag[index] < 0x21 || tag[index] == '"' || tag[index] == 0x7f {
			return ""
		}
	}
	return tag
}

func packageEncoding(response *http.Response) error {
	encoding := response.Header.Values("Content-Encoding")
	if len(encoding) == 0 || len(encoding) == 1 && strings.EqualFold(strings.TrimSpace(encoding[0]), "identity") {
		return nil
	}
	return externalError(ErrorUnsupportedEncoding, "fetch", "", fmt.Errorf("content encoding is not identity"))
}
