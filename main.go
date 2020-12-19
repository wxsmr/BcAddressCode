package main

import (
	"BcAddressCode04/base58"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

const VERSION = 0x00

func main1() {
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
	//系统的api
	pubKey := elliptic.Marshal(curve, x, y)
	//x坐标：32字节，y坐标32字节
	fmt.Println("非压缩格式的公钥：", pubKey)
	fmt.Println("非压缩公钥格式的长度：", len(pubKey))

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

func main() {
	address := GetAddress()

	isValid := CheckAdd(address)

	fmt.Println(isValid)
}

/**
 * 生成一个比特币的地址
 */
func GetAddress() string {
	curve := elliptic.P256()

	pri, _ := GenerateKey(curve)

	pub := GetUnCompressPub(curve, pri)

	//1、sha256
	hash256 := SHA256Hash(pub)
	//ripemd160
	ripemd := Ripemd160Hash(hash256)

	//version
	versionRipemd := append([]byte{VERSION}, ripemd...)

	//double hash
	hash1 := SHA256Hash(versionRipemd)
	hash2 := SHA256Hash(hash1)

	check := hash2[:4]

	add := append(versionRipemd, check...)
	return base58.Encode(add)
}

/**
 * 产生私钥
 */
func GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func GetUnCompressPub(curve elliptic.Curve, pri *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(curve, pri.X, pri.Y)
}

func SHA256Hash(msg []byte) []byte {
	sha256Hash := sha256.New()
	sha256Hash.Write(msg)
	return sha256Hash.Sum(nil)
}

func Ripemd160Hash(msg []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(msg)
	return ripemd.Sum(nil)
}

/**
 * 校验给定的比特币的地址是否有效
 */
func CheckAdd(add string) bool {
	//1、反编码
	deAddBytes := base58.Decode(add)
	//2、截取校验位
	deCheck := deAddBytes[len(deAddBytes)-4:]
	//3、计算校验位
	//a、获取反编码去除后四位的内容
	versionRipemd160 := deAddBytes[:len(deAddBytes)-4]
	//b、双hash
	sha256Hash := sha256.New()
	sha256Hash.Write(versionRipemd160)
	hash1 := sha256Hash.Sum(nil)

	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//c、截取前4位 作为校验位
	check := hash2[:4]

	//4、使用截取的校验位 与 计算的校验位 进行比较
	//isValid := bytes.Compare(deCheck, check)
	//if isValid == 0{
	//	fmt.Println("恭喜，有效")
	//	return true
	//}
	return bytes.Compare(deCheck, check) == 0
}
