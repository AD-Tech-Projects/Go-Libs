package logger

import (
	"fmt"
	"strconv"
	"strings"
)

func parseToString(value any) string {
	switch v := any(value).(type) {
	case string:
		return v
	case bool:
		return parseBool(v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return parseNumber(v)
	case []any:
		return parseArray(v)
	case map[string]any:
		return parseMap(v)
	default:
		return "[UNKNOWN]"
	}
}

func parseArray(arr []any) string {
	var strValues []string
	for _, item := range arr {
		strValues = append(strValues, parseToString(item))
	}
	return "[" + strings.Join(strValues, ", ") + "]"
}

func parseMap(m map[string]any) string {
	var strValues []string
	for key, item := range m {
		strValues = append(strValues, fmt.Sprintf("%s: %s", key, parseToString(item)))
	}
	return "{" + strings.Join(strValues, ", ") + "}"
}

func parseNumber[T any](value T) string {
	switch v := any(value).(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return parseIntegerToSring(v)
	case float32:
		return parseFloatToSring(float64(v))
	case float64:
		return parseFloatToSring(v)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func parseIntegerToSring(value any) string {
	return fmt.Sprintf("%d", value)
}

func parseFloatToSring(value float64) string {
	strValue := strconv.FormatFloat(value, 'f', -1, 64)
	parts := strings.Split(strValue, ".")

	floatWithoutDecimal := strconv.FormatFloat(value, 'f', 1, 64)

	if len(parts) < 2 {
		return floatWithoutDecimal
	}

	floatPart := parts[1]
	allZeros := true
	for _, digit := range floatPart {
		if digit != '0' {
			allZeros = false
			break
		}
	}

	if allZeros {
		return floatWithoutDecimal
	}

	precision := len(floatPart)
	return strconv.FormatFloat(value, 'f', precision, 64)
}

func parseBool(value bool) string {
	return fmt.Sprintf("%t", value)
}
