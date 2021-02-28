package utils

func ContainsString(stack []string, needle string) int {
	for i, item := range stack {
		if item == needle {
			return i
		}
	}
	return -1
}

func ContainsInt(stack []int, needle int) int {
	for i, item := range stack {
		if item == needle {
			return i
		}
	}
	return -1
}
