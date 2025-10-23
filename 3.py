import requests
import json
import hashlib
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

# 这里添加注释内容
print("1111111")
class JinYiAPI:
    def __init__(self):
        self.sm4_key_hex = "31353438343932353932303333393539"
        self.sm4_key = bytes.fromhex(self.sm4_key_hex)
        self.sign_key = "aAr9MVS9j1"

        self.base_url = "https://jinyi-api.jhzxyy.cn/app"

        # 完整的请求头
        self.headers = {
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "connection": "keep-alive",
            "content-type": "application/x-www-form-urlencoded",
            "host": "jinyi-api.jhzxyy.cn",
            "origin": "https://jinyi-wechat.jhzxyy.cn",
            "referer": "https://jinyi-wechat.jhzxyy.cn/",
            "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        }

        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def sm4_decrypt_ecb(self, encrypted_hex):
        """SM4 ECB模式解密 - 与JavaScript版本保持一致"""
        try:
            # 清理输入数据
            encrypted_hex = encrypted_hex.strip().replace(' ', '').replace('\n', '').replace('\r', '')

            if not all(c in '0123456789abcdefABCDEF' for c in encrypted_hex):
                return f"无效的十六进制数据: {encrypted_hex[:100]}..."

            # 检查长度是否为16的倍数（字节）
            if len(encrypted_hex) % 32 != 0:  # 32 hex chars = 16 bytes
                return f"数据长度不正确: {len(encrypted_hex)} 字符"

            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(self.sm4_key, SM4_DECRYPT)

            ciphertext = bytes.fromhex(encrypted_hex)
            decrypted = crypt_sm4.crypt_ecb(ciphertext)

            # 关键修正：移除所有空字节，然后尝试UTF-8解码
            decrypted_clean = decrypted.rstrip(b'\x00')

            # 尝试UTF-8解码
            try:
                result = decrypted_clean.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                # 如果UTF-8失败，尝试其他方式
                try:
                    result = decrypted_clean.decode('utf-8')
                except:
                    result = decrypted_clean.hex()

            return result

        except Exception as e:
            return f"解密失败: {str(e)}, 数据长度: {len(encrypted_hex)}"

    def sm4_encrypt_ecb(self, plaintext):
        """SM4 ECB模式加密 - 与JavaScript版本保持一致"""
        try:
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(self.sm4_key, SM4_ENCRYPT)

            # 将数据转换为字节
            if isinstance(plaintext, dict):
                text_bytes = json.dumps(plaintext, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            else:
                text_bytes = str(plaintext).encode('utf-8')

            # 填充到16字节的倍数（使用空字节）
            block_size = 16
            if len(text_bytes) % block_size != 0:
                padding_size = block_size - (len(text_bytes) % block_size)
                text_bytes += b'\x00' * padding_size

            encrypted = crypt_sm4.crypt_ecb(text_bytes)
            return encrypted.hex()

        except Exception as e:
            return f"加密失败: {str(e)}"

    def generate_sign(self, data_dict):
        """生成签名"""
        try:
            first_md5 = hashlib.md5(self.sign_key.encode('utf-8')).hexdigest()
            data_json = json.dumps(data_dict, separators=(',', ':'), ensure_ascii=False)
            sign_data = first_md5 + data_json
            return hashlib.md5(sign_data.encode('utf-8')).hexdigest()
        except Exception as e:
            return f"签名生成失败: {str(e)}"

    def option1_normal_request(self):
        """选项1: 正常请求流程"""
        print("\n" + "=" * 80)
        print("选项1: 正常请求流程")
        print("=" * 80)

        # 1. 输入请求体加密密文
        encrypted_data = input("请输入请求体加密密文: ").strip()
        if not encrypted_data:
            print("未输入数据")
            return

        print(f"\n步骤1: 分析请求数据")
        print("-" * 40)

        # 解密请求数据
        decrypted_request = self.sm4_decrypt_ecb(encrypted_data)
        print(f"解密后的请求数据: {decrypted_request}")

        # 尝试解析为JSON
        try:
            request_json = json.loads(decrypted_request)
            print("✅ 成功解析为JSON格式:")
            print(json.dumps(request_json, indent=2, ensure_ascii=False))
        except json.JSONDecodeError as e:
            print(f"❌ 解密结果不是有效的JSON格式: {e}")
            return

        print(f"\n步骤2: 生成签名")
        print("-" * 40)

        # 生成签名
        sign = self.generate_sign(request_json)
        print(f"生成的Sign: {sign}")

        print(f"\n步骤3: 发送请求")
        print("-" * 40)

        # 准备请求头
        request_headers = self.headers.copy()
        request_headers["sign"] = sign

        # 使用原始加密数据发送请求
        data_to_send = encrypted_data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        print(f"发送数据长度: {len(data_to_send)} 字符")
        print(f"请求URL: {self.base_url}")

        try:
            response = self.session.post(
                url=self.base_url,
                data={"data": data_to_send},
                headers=request_headers,
                timeout=30
            )

            print(f"响应状态码: {response.status_code}")

            if response.status_code == 200:
                response_text = response.text.strip()
                print(f"\n步骤4: 处理响应数据")
                print("-" * 40)
                print(f"原始响应数据长度: {len(response_text)} 字符")
                print(f"原始响应数据 (前200字符):")
                print(response_text[:200] + "..." if len(response_text) > 200 else response_text)

                # 尝试解密响应
                if response_text and all(c in '0123456789abcdefABCDEF' for c in response_text):
                    print(f"\n步骤5: 解密响应数据")
                    print("-" * 40)
                    decrypted_response = self.sm4_decrypt_ecb(response_text)
                    print(f"解密后的响应: {decrypted_response}")

                    # 尝试解析为JSON
                    try:
                        response_json = json.loads(decrypted_response)
                        print("✅ 响应JSON解析成功:")
                        print(json.dumps(response_json, indent=2, ensure_ascii=False))
                    except json.JSONDecodeError as e:
                        print(f"❌ 响应不是JSON格式: {e}")
                else:
                    print("响应数据不是十六进制格式，可能是明文或错误信息")
                    print(f"响应内容: {response_text}")

            else:
                print(f"❌ 请求失败，状态码: {response.status_code}")
                print(f"响应内容: {response.text}")

        except requests.exceptions.Timeout:
            print("❌ 请求超时")
        except requests.exceptions.ConnectionError:
            print("❌ 连接错误")
        except Exception as e:
            print(f"❌ 请求异常: {e}")

    def option2_decrypt_request(self):
        """选项2: 直接解密请求体加密密文"""
        print("\n" + "=" * 80)
        print("选项2: 直接解密请求体加密密文")
        print("=" * 80)

        encrypted_data = input("请输入请求体加密密文: ").strip()
        if not encrypted_data:
            print("未输入数据")
            return

        print(f"\n加密数据分析:")
        print("-" * 40)
        encrypted_data = encrypted_data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        print(f"密文长度: {len(encrypted_data)} 字符")
        print(f"密文前100字符: {encrypted_data[:100]}...")

        # 解密
        decrypted = self.sm4_decrypt_ecb(encrypted_data)
        print(f"\n解密结果: {decrypted}")

        # 尝试解析为JSON
        try:
            request_data = json.loads(decrypted)
            print("✅ 成功解析为JSON:")
            print(json.dumps(request_data, indent=2, ensure_ascii=False))
        except json.JSONDecodeError:
            print("❌ 解密结果不是有效的JSON格式")

    def option3_decrypt_response(self):
        """选项3: 直接解密响应数据"""
        print("\n" + "=" * 80)
        print("选项3: 直接解密响应数据")
        print("=" * 80)

        response_data = input("请输入响应数据密文: ").strip()
        if not response_data:
            print("未输入数据")
            return

        print(f"\n响应数据分析:")
        print("-" * 40)
        response_data = response_data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        print(f"密文长度: {len(response_data)} 字符")
        print(f"密文前100字符: {response_data[:100]}...")

        # 解密
        decrypted = self.sm4_decrypt_ecb(response_data)
        print(f"\n解密结果: {decrypted}")

        # 尝试解析为JSON
        try:
            response_json = json.loads(decrypted)
            print("✅ 成功解析为JSON:")
            print(json.dumps(response_json, indent=2, ensure_ascii=False))
        except json.JSONDecodeError:
            print("❌ 解密结果不是有效的JSON格式")

    def display_menu(self):
        """显示菜单"""
        print("\n" + "=" * 50)
        print("金医系统API工具")
        print("=" * 50)
        print("1. 正常请求方式")
        print("   - 输入请求体加密密文")
        print("   - 解密查看JSON格式")
        print("   - 生成Sign值")
        print("   - 发起请求并解密响应")
        print("2. 直接解密请求体加密密文")
        print("3. 直接解密响应数据")
        print("4. 退出程序")
        print("=" * 50)

    def run(self):
        """运行主程序"""
        while True:
            self.display_menu()
            choice = input("\n请选择操作 (1/2/3/4): ").strip()

            if choice == "1":
                self.option1_normal_request()
            elif choice == "2":
                self.option2_decrypt_request()
            elif choice == "3":
                self.option3_decrypt_response()
            elif choice == "4":
                print("退出程序")
                break
            else:
                print("无效选择，请重新输入")

            input("\n按回车键继续...")


def main():
    """主函数"""
    api = JinYiAPI()
    api.run()


if __name__ == "__main__":
    main()
