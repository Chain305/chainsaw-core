package pgstore

import (
	"context"
	"database/sql/driver"
	"strconv"
	"strings"
)

func rewritePlaceholders(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	inQuote := false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if ch == '\'' {
			inQuote = !inQuote
			b.WriteByte(ch)
		} else if ch == '?' && !inQuote {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

type rewriteConnector struct {
	base driver.Connector
}

func (c *rewriteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &rewriteConn{inner: conn}, nil
}

func (c *rewriteConnector) Driver() driver.Driver {
	return c.base.Driver()
}

type rewriteConn struct {
	inner driver.Conn
}

func (c *rewriteConn) Prepare(query string) (driver.Stmt, error) {
	return c.inner.Prepare(rewritePlaceholders(query))
}

func (c *rewriteConn) Close() error { return c.inner.Close() }

func (c *rewriteConn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *rewriteConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if execer, ok := c.inner.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, rewritePlaceholders(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *rewriteConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if queryer, ok := c.inner.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, rewritePlaceholders(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *rewriteConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if beginner, ok := c.inner.(driver.ConnBeginTx); ok {
		return beginner.BeginTx(ctx, opts)
	}
	return c.inner.Begin()
}

func (c *rewriteConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if preparer, ok := c.inner.(driver.ConnPrepareContext); ok {
		return preparer.PrepareContext(ctx, rewritePlaceholders(query))
	}
	return c.inner.Prepare(rewritePlaceholders(query))
}

func (c *rewriteConn) Ping(ctx context.Context) error {
	if pinger, ok := c.inner.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (c *rewriteConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.inner.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *rewriteConn) IsValid() bool {
	if validator, ok := c.inner.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}
