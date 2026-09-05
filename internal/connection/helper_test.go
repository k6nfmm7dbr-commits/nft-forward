package connection

import "os"

// writeFileImpl 是测试写文件的小工具（单独一个文件，避免主测试文件引入 os）。
func writeFileImpl(path, content string, mode uint32) error {
	return os.WriteFile(path, []byte(content), os.FileMode(mode))
}
