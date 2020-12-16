package main

import (
	"BcAddressCode04/base58"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	fmt.Println("hello world")
	//第一步，生成私钥和公钥
	curve := elliptic.P256()
	//ecdsa.GenerateKey(curve, rand.Reader)
	//x和y可以组成公钥
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//将x和y组成公钥，转换为[]byte类型
	//公钥：x坐标+y坐标
	pubKey := append(x.Bytes(), y.Bytes()...)

	//第二步，hash计算
	//sha256
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKey)
	pubHash256 := sha256Hash.Sum(nil)
	//ripemd160：github下载
	ripemd := ripemd160.New()
	ripemd.Write(pubHash256)
	pubRipemd160 := ripemd.Sum(nil)

	//第三步，添加版本号前缀
	versionPubRipemd160 := append([]byte{0x00}, pubRipemd160...)

	//第四步，计算校验位
	//a、sha256
	sha256Hash.Reset() //重置
	sha256Hash.Write(versionPubRipemd160)
	hash1 := sha256Hash.Sum(nil)
	//b、sha256
	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//c、取前4个字节
	//如何截取[]byte的前四个内容
	// hash[开始:结尾]：前闭后开
	check := hash2[0:4]

	//第五步，拼接校验位, 得到地址，[]byte类型
	addBytes := append(versionPubRipemd160, check...)

	fmt.Println("地址：", addBytes)

	//第六步，对地址进行base58编码
	//github：go base58
	address := base58.Encode(addBytes)
	fmt.Println("生成的新的比特币地址：", address)
}
