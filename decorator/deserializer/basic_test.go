package deserializer

import (
	"encoding/xml"
	"errors"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

// Ensure *BasicDeserializer implements
var _ Deserializer[string] = (*BasicDeserializer[string])(nil)

// Mock type implementing json.Unmarshaler
type jsonMock struct {
	Value string
}

func (j *jsonMock) UnmarshalJSON(data []byte) error {
	if string(data) == "error" {
		return errors.New("json unmarshal error")
	}
	j.Value = "json:" + string(data)
	return nil
}

// Mock type implementing encoding.TextUnmarshaler
type textMock struct {
	Value string
}

func (t *textMock) UnmarshalText(text []byte) error {
	if string(text) == "error" {
		return errors.New("text unmarshal error")
	}
	t.Value = "text:" + string(text)
	return nil
}

// Mock type implementing encoding.BinaryUnmarshaler
type binaryMock struct {
	Value string
}

func (b *binaryMock) UnmarshalBinary(data []byte) error {
	if string(data) == "error" {
		return errors.New("binary unmarshal error")
	}
	b.Value = "binary:" + string(data)
	return nil
}

// Mock type implementing xml.Unmarshaler
type xmlMock struct {
	Value string
}

func (x *xmlMock) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	if s == "error" {
		return errors.New("xml unmarshal error")
	}
	x.Value = "xml:" + s
	return nil
}

// Mock type implementing both json.Unmarshaler and encoding.TextUnmarshaler
type multiMock struct {
	Value string
}

func (m *multiMock) UnmarshalJSON(data []byte) error {
	if string(data) != `{"valid_json":true}` {
		return errors.New("not expected json")
	}
	m.Value = "from_json"
	return nil
}

func (m *multiMock) UnmarshalText(text []byte) error {
	if string(text) != "fallback_text" {
		return errors.New("not expected text")
	}
	m.Value = "from_text"
	return nil
}

func TestNewBasicDeserializer(t *testing.T) {
	d := NewBasicDeserializer[string]()
	assert.NotNil(t, d)
}

func TestBasicDeserializer_JSONUnmarshaler(t *testing.T) {
	dValue := NewBasicDeserializer[jsonMock]()
	resVal, err := dValue.Deserialize([]byte("test_data"))
	assert.NoError(t, err)
	assert.Equal(t, "json:test_data", resVal.Value)

	dPtr := NewBasicDeserializer[*jsonMock]()
	resPtr, err := dPtr.Deserialize([]byte("test_data_ptr"))
	assert.NoError(t, err)
	assert.NotNil(t, resPtr)
	assert.Equal(t, "json:test_data_ptr", resPtr.Value)
}

func TestBasicDeserializer_TextUnmarshaler(t *testing.T) {
	dValue := NewBasicDeserializer[textMock]()
	resVal, err := dValue.Deserialize([]byte("test_text"))
	assert.NoError(t, err)
	assert.Equal(t, "text:test_text", resVal.Value)

	dPtr := NewBasicDeserializer[*textMock]()
	resPtr, err := dPtr.Deserialize([]byte("test_text_ptr"))
	assert.NoError(t, err)
	assert.NotNil(t, resPtr)
	assert.Equal(t, "text:test_text_ptr", resPtr.Value)
}

func TestBasicDeserializer_BinaryUnmarshaler(t *testing.T) {
	dValue := NewBasicDeserializer[binaryMock]()
	resVal, err := dValue.Deserialize([]byte{0x01, 0x02, 0x03})
	assert.NoError(t, err)
	assert.Equal(t, "binary:\x01\x02\x03", resVal.Value)

	dPtr := NewBasicDeserializer[*binaryMock]()
	resPtr, err := dPtr.Deserialize([]byte{0x04, 0x05})
	assert.NoError(t, err)
	assert.NotNil(t, resPtr)
	assert.Equal(t, "binary:\x04\x05", resPtr.Value)
}

func TestBasicDeserializer_XMLUnmarshaler(t *testing.T) {
	dValue := NewBasicDeserializer[xmlMock]()
	resVal, err := dValue.Deserialize([]byte("<xmlMock>test_xml</xmlMock>"))
	assert.NoError(t, err)
	assert.Equal(t, "xml:test_xml", resVal.Value)

	dPtr := NewBasicDeserializer[*xmlMock]()
	resPtr, err := dPtr.Deserialize([]byte("<xmlMock>test_xml_ptr</xmlMock>"))
	assert.NoError(t, err)
	assert.NotNil(t, resPtr)
	assert.Equal(t, "xml:test_xml_ptr", resPtr.Value)
}

func TestBasicDeserializer_MultiUnmarshaler_Fallback(t *testing.T) {
	d := NewBasicDeserializer[multiMock]()

	// First unmarshaler (JSON) succeeds
	res1, err := d.Deserialize([]byte(`{"valid_json":true}`))
	assert.NoError(t, err)
	assert.Equal(t, "from_json", res1.Value)

	// First unmarshaler fails, second (Text) succeeds
	res2, err := d.Deserialize([]byte("fallback_text"))
	assert.NoError(t, err)
	assert.Equal(t, "from_text", res2.Value)
}

func TestBasicDeserializer_Errors(t *testing.T) {
	// JSON unmarshaler error
	dJSON := NewBasicDeserializer[jsonMock]()
	_, err := dJSON.Deserialize([]byte("error"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize data")
	assert.Contains(t, err.Error(), "json unmarshal error")

	// Text unmarshaler error
	dText := NewBasicDeserializer[textMock]()
	_, err = dText.Deserialize([]byte("error"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize data")
	assert.Contains(t, err.Error(), "text unmarshal error")

	// Binary unmarshaler error
	dBinary := NewBasicDeserializer[binaryMock]()
	_, err = dBinary.Deserialize([]byte("error"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize data")
	assert.Contains(t, err.Error(), "binary unmarshal error")

	// XML unmarshaler error
	dXML := NewBasicDeserializer[xmlMock]()
	_, err = dXML.Deserialize([]byte("<xmlMock>error</xmlMock>"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize data")
	assert.Contains(t, err.Error(), "xml unmarshal error")

	// Non-unmarshaler type
	dInt := NewBasicDeserializer[int]()
	_, err = dInt.Deserialize([]byte("123"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize data")
}
