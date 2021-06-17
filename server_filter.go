package ldap

import (
	"fmt"
	"regexp"
	"strconv"
	"unicode"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var debug = false

func ServerApplyFilter(f *ber.Packet, entry *Entry) (bool, uint16) {
	//if debug {
	//	fmt.Println("Server apply filter called")
	//	ber.PrintPacket(f)
	//}
	switch f.Tag {
	default:
		//log.Fatalf("Unknown LDAP filter code: %d", f.Tag)
		return false, LDAPResultOperationsError
	case FilterEqualityMatch:
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		value := f.Children[1].Value.(string)
		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, attribute) {
				for _, v := range a.Values {
					if caselessMatch(v, value) {
						return true, LDAPResultSuccess
					}
				}
			}
		}
	case FilterPresent:
		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, f.Data.String()) {
				return true, LDAPResultSuccess
			}
		}
	case FilterAnd:
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != LDAPResultSuccess {
				return false, exitCode
			}
			if !ok {
				return false, LDAPResultSuccess
			}
		}
		return true, LDAPResultSuccess
	case FilterOr:
		anyOk := false
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != LDAPResultSuccess {
				return false, exitCode
			} else if ok {
				anyOk = true
			}
		}
		if anyOk {
			return true, LDAPResultSuccess
		}
	case FilterNot:
		if len(f.Children) != 1 {
			return false, LDAPResultOperationsError
		}
		ok, exitCode := ServerApplyFilter(f.Children[0], entry)
		if exitCode != LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, LDAPResultSuccess
		}
	case FilterSubstrings:
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		matching := []string{}
		for _, child := range f.Children[1].Children {
			bytes := string(child.Data.Bytes())
			switch child.Tag {
			case FilterSubstringsInitial:
				matching = append(matching, []string{bytes, ""}...)
			case FilterSubstringsAny:
				if len(matching) == 0 {
					matching = append(matching, []string{"", bytes, ""}...)
				} else {
					matching = append(matching, []string{bytes, ""}...)
				}
			case FilterSubstringsFinal:
				if len(matching) == 0 {
					matching = append(matching, []string{"", bytes}...)
				} else {
					matching = append(matching, bytes)
				}
			}
		}

		fmt.Printf("matching: %q\n", matching)
		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, attribute) {
				for _, v := range a.Values {
					//func deepMatch(str string, matching []string, matchCase bool) bool
					if deepMatch(v, matching, false) {
						return true, LDAPResultSuccess
					}
				}
			}
		}
	case FilterGreaterOrEqual:
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)

		value := f.Children[1].Value.(string)
		valueNum, err := strconv.Atoi(value)
		Numeric := false
		if err == nil {
			Numeric = true
		}
		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, attribute) {
				for _, v := range a.Values {
					if Numeric {
						if num, err := strconv.Atoi(v); err == nil {
							return num >= valueNum, LDAPResultSuccess
						}
					}
					return caselessCompare(v, value) > -1, LDAPResultSuccess
				}
			}
		}
	case FilterLessOrEqual:
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)

		value := f.Children[1].Value.(string)
		valueNum, err := strconv.Atoi(value)
		Numeric := false
		if err == nil {
			Numeric = true
		}
		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, attribute) {
				for _, v := range a.Values {
					if Numeric {
						if num, err := strconv.Atoi(v); err == nil {
							return num <= valueNum, LDAPResultSuccess
						}
					}
					return caselessCompare(v, value) < 1, LDAPResultSuccess
				}
			}
		}
	case FilterApproxMatch:
		// Per RFC4511 Spec:

		/*
			4.5.1.7.6.  SearchRequest.filter.approxMatch

				An approxMatch filter is TRUE when there is a value of the attribute
				type or subtype for which some locally-defined approximate matching
				algorithm (e.g., spelling variations, phonetic match, etc.) returns
				TRUE.  If a value matches for equality, it also satisfies an
				approximate match.  If approximate matching is not supported for the
				attribute, this filter item should be treated as an equalityMatch.
		*/

		// An approximate match filter is not generically programmable with closure
		// for all languages, as one could interpret this to mean a distance
		// function or an approximation by some other means.  Ultimately these fall
		// short of what the requestor may have been initially looking to match.
		// There is a programmable string search tool providing an expression-like
		// language for strings, and this is regular expressions.  We choose to
		// implement regular expressions here by looking for the starting character
		// '^' and the last character of '$'.
		//
		// Example:
		// ldapsearch -H ldap://localhost:1389 -x -b o=test $'cn~=^\(?i\).*ziggy.*$'
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		value := f.Children[1].Value.(string)
		isRegex := false
		if len(value) > 2 && value[0] == '^' && value[len(value)-1] == '$' {
			isRegex = true
		}
		if !isRegex {
			// Fail back to simple match
			for _, a := range entry.Attributes {
				if caselessMatch(a.Name, attribute) {
					for _, v := range a.Values {
						if caselessMatch(v, value) {
							return true, LDAPResultSuccess
						}
					}
				}
			}
		} else {
			// Compile and match regexp
			re := regexp.MustCompile(value)
			for _, a := range entry.Attributes {
				if caselessMatch(a.Name, attribute) {
					for _, v := range a.Values {
						if re.MatchString(v) {
							return true, LDAPResultSuccess
						}
					}
				}
			}
		}
	case FilterExtensibleMatch: // TODO
		switch len(f.Children) {
		default:
			return false, LDAPResultOperationsError
		case 2, 3:
		}

		var rule, attribute, value string
		var intValue int
		var err error

		for _, child := range f.Children {
			switch child.Tag {
			case 1:
				rule = child.Value.(string)
			case 2:
				attribute = child.Value.(string)
			case 3:
				value = child.Value.(string)
			default:
			}
		}

		match := 'L' // Caseless
		switch rule {
		case "caseExactMatch":
			// Example: ldapsearch -H ldap://localhost:1389 -x -b o=test '(&(uid:caseExactMatch:=ziggy)(objectClass=person))'
			match = 'F'
		case "1.2.840.113556.1.4.803": // LDAP_MATCHING_RULE_BIT_AND
			match = '&'
			intValue, err = strconv.Atoi(value)
			if err != nil {
				return false, LDAPResultOperationsError
			}
		case "1.2.840.113556.1.4.804": // LDAP_MATCHING_RULE_BIT_OR
			match = '|'
			intValue, err = strconv.Atoi(value)
			if err != nil {
				return false, LDAPResultOperationsError
			}
		case "1.2.840.113556.1.4.1941": // LDAP_MATCHING_RULE_IN_CHAIN
			// TODO: Implement nested groups
			return false, LDAPResultOperationsError
		case "":
		default:
			return false, LDAPResultOperationsError
		}

		for _, a := range entry.Attributes {
			if caselessMatch(a.Name, attribute) || attribute == "" {
				for _, v := range a.Values {
					switch match {
					case 'L':
						if caselessMatch(v, value) {
							return true, LDAPResultSuccess
						}
					case 'F':
						if casefulMatch(v, value) {
							return true, LDAPResultSuccess
						}
					case '|':
						iv, err := strconv.Atoi(v)
						if err == nil && (intValue&iv) > 0 {
							return true, LDAPResultSuccess
						}
					case '&':
						iv, err := strconv.Atoi(v)
						if err == nil && (intValue&iv) == intValue {
							return true, LDAPResultSuccess
						}
					}
				}
			}
		}
	}

	return false, LDAPResultSuccess
}

func casefulMatch(A, B string) bool {
	for len(A) > 0 && len(B) > 0 {
		rA, sizeA := utf8.DecodeRuneInString(A)
		rB, sizeB := utf8.DecodeRuneInString(B)
		if rA != rB {
			return false
		}
		A = A[sizeA:]
		B = B[sizeB:]
	}
	return len(A) == 0 && len(B) == 0
}

func caselessMatch(A, B string) bool {
	for len(A) > 0 && len(B) > 0 {
		rA, sizeA := utf8.DecodeRuneInString(A)
		rB, sizeB := utf8.DecodeRuneInString(B)
		if unicode.ToLower(rA) != unicode.ToLower(rB) {
			return false
		}
		A = A[sizeA:]
		B = B[sizeB:]
	}
	return len(A) == 0 && len(B) == 0
}

func caselessCompare(A, B string) int {
	for len(A) > 0 && len(B) > 0 {
		rA, sizeA := utf8.DecodeRuneInString(A)
		rB, sizeB := utf8.DecodeRuneInString(B)
		if unicode.ToLower(rA) != unicode.ToLower(rB) {
			if unicode.ToLower(rA) < unicode.ToLower(rB) {
				return -1
			} else {
				return 1
			}
		}
		if len(A) == 1 || len(B) == 1 {
			break
		}
		A = A[sizeA:]
		B = B[sizeB:]
	}
	if len(A) == len(B) {
		return 0
	} else if len(A) < len(B) {
		return -1
	}
	return 1
}

func deepMatch(str string, matching []string, matchCase bool) bool {
	var runePattern, runeStr rune
	var sizePattern, sizeStr int
	for len(matching) > 0 {
		switch matching[0] {
		default:
			runePattern, sizePattern = utf8.DecodeRuneInString(matching[0])
			if len(str) < sizePattern {
				return false
			}
			runeStr, sizeStr = utf8.DecodeRuneInString(str)
			if matchCase && runeStr != runePattern {
				return false
			}
			if !matchCase && unicode.ToLower(runeStr) != unicode.ToLower(runePattern) {
				return false
			}
		case "":
			if len(matching) == 1 {
				return true
			}
			_, size := utf8.DecodeRuneInString(str)
			return deepMatch(str, matching[1:], matchCase) ||
				(len(str) > 0 && deepMatch(str[size:], matching, matchCase))
		}
		str = str[sizeStr:]
		matching[0] = matching[0][sizePattern:]
	}
	return len(str) == 0 && len(matching) == 0
}
