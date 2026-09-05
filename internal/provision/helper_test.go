package provision

import (
	"context"
	"net"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// netTCPAddr 是 net.TCPAddr 的别名，避免测试里到处写类型断言。
type netTCPAddr = net.TCPAddr

// netListen 在随机空闲端口上起一个 TCP 监听（测试占用探测用）。
func netListen() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// seedRule 在指定库里插入一条使用给定监听端口的规则。
func seedRule(dbPath string, listenPort int) error {
	db, err := database.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = forward.NewStore(db.DB).Create(context.Background(), &forward.Rule{
		Name: "seed", Enabled: true, Protocol: "tcp",
		ListenPort: listenPort, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	return err
}

// dropRulesTable 删掉 rules 表（模拟 schema 损坏）。
func dropRulesTable(dbPath string) error {
	db, err := database.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec("DROP TABLE rules")
	return err
}
