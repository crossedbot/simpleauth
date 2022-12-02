package models

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// Options represents a map of optional user attributes.
type Options map[string]string

// Value returns the SQL driver value for the given options. This implements the
// gorm.Valuer interface.
func (o *Options) Value() (driver.Value, error) {
	if o == nil {
		return nil, nil
	}
	b, err := o.MarshalJSON()
	return string(b), err
}

// Scan scans the given bytes or string value into the given options. This
// implements the sql.Scanner interface.
func (o *Options) Scan(val interface{}) error {
	if val == nil {
		*o = make(Options)
		return nil
	}
	var b []byte
	switch v := val.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("Unknown value type '%T'", val)
	}
	var v Options
	err := json.Unmarshal(b, &v)
	*o = v
	return err
}

// MarshalJSON marshals the options value and encodes as JSON.
func (o Options) MarshalJSON() ([]byte, error) {
	if o == nil {
		return []byte("null"), nil
	}
	v := (map[string]string)(o)
	return json.Marshal(v)
}

// UnmarshalJSON unmarshals the given JSON bytes into the options.
func (o *Options) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*o = make(Options)
		return nil
	}
	var v map[string]string
	err := json.Unmarshal(b, &v)
	*o = v
	return err
}

// GormDataType returns the GORM datatype of the options. This implements the
// schema.GormDataTypeInterface interface.
func (o Options) GormDataType() string {
	return "options"
}

// GormDBDataType returns the DB datatype for the given database's dialect. This
// implements the migrator.GormDataTypeInterface interface.
func (o Options) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Dialector.Name() {
	case "sqlite":
		return "JSON"
	case "mysql":
		return "JSON"
	case "postgres":
		return "JSONB"
	case "sqlserver":
		return "NVARCHAR(MAX)"
	}
	return ""
}

// GormValue returns the GORM expression for the given database and options.
// This implements the gorm.Valuer interface.
func (o Options) GormValue(ctx context.Context, db *gorm.DB) clause.Expr {
	data, _ := o.MarshalJSON()
	switch db.Dialector.Name() {
	case "mysql":
		v, ok := db.Dialector.(*mysql.Dialector)
		if ok && !strings.Contains(v.ServerVersion, "MariaDB") {
			return gorm.Expr("CAST(? AS JSON)", string(data))
		}
	}
	return gorm.Expr("?", string(data))
}
