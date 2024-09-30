package com.gzu;

public class work1 {
//1. 会话安全性
//● 会话劫持和防御
  //会话劫持
  //攻击者获得了会话ID，然后用这个ID来模仿用户行为
    // 假设攻击者已经通过某种手段获得了会话ID
    $stolen_session_id = "攻击者获得的会话ID";

    // 使用偷来的会话ID来初始化会话
    session_id($stolen_session_id);
    session_start();

//会话防御
// 在PHP中设置会话Cookie
session_start();
// 设置HttpOnly和Secure标志
    $cookieParams = session_get_cookie_params();
    setcookie(session_name(), session_id(), time() + $cookieParams["lifetime"],$cookieParams["path"], $cookieParams["domain"], true, true); // HttpOnly和Secure

//● 跨站脚本攻击（XSS）和防御
  // PHP中防止XSS攻击
function escape($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

    // 使用escape函数来转义输出
    echo escape($_POST['user_input']);

//● 跨站请求伪造（CSRF）和防御
  // PHP中生成和验证CSRF令牌
session_start();
if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

  // 在表单中包含CSRF令牌
    echo '<form action="process.php" method="post">';
    echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
    echo '<input type="submit" value="Submit">';
    echo '</form>';

  // 在process.php中验证CSRF令牌
if ($_POST['csrf_token'] !==$_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }

//2. 分布式会话管理
//● 分布式环境下的会话同步问题
    //在分布式系统中，用户可能会遇到服务器出现故障；可能是会话本地存储；网络高负载的情况等问题，导致同步中的数据丢失
//● Session集群解决方案
//    使用Session复制，将每个服务器的Session信息复制到其他服务器。
//    使用Session持久化，将Session信息存储在数据库或文件系统中。
//    使用分布式缓存（如Redis）存储Session信息。
//● 使用Redis等缓存技术实现分布式会话
    //
    <?php
    class RedisSessionHandler implements SessionHandlerInterface
    {
        private $redis;
        private $ttl;

        public function __construct()
        {
            $this->redis = new Redis();
            $this->redis->connect('127.0.0.1', 6379); // 替换为你的Redis服务器地址和端口
            $this->ttl = ini_get('session.gc_maxlifetime');
        }

        public function open($savePath,$sessionName)
        {
            return true;
        }

        public function close()
        {
            return true;
        }

        public function read($sessionId)
        {
            return $this->redis->get($sessionId) ?: '';
        }

        public function write($sessionId,$data)
        {
            if ($this->ttl > 0) {
                $this->redis->setex($sessionId, $this->ttl,$data);
            } else {
                $this->redis->set($sessionId, $data);
            }
            return true;
        }

        public function destroy($sessionId)
        {
            $this->redis->del($sessionId);
            return true;
        }

        public function gc($maxLifetime)
        {
            // Redis 会自动处理过期的键，所以这里不需要实现具体的垃圾回收逻辑
            return true;
        }
    }

  // 创建自定义会话处理器实例
    $handler = new RedisSessionHandler();

    // 注册自定义会话处理器
    session_set_save_handler($handler, true);

    // 启动会话
    session_start();

//3. 会话状态的序列化和反序列化
//● 会话状态的序列化和反序列化
    //会话状态的序列化是指将内存中的会话数据转换成一种可以存储或传输的格式的过程
    // 相对应地，反序列化则是将这种格式转换回原始的内存数据结构。
//● 为什么需要序列化会话状态
    //持久化存储：序列化允许将会话数据保存到文件系统、数据库或缓存中，以便在服务器重启后能够恢复会话状态。
    //网络传输：在分布式系统中，序列化后的会话状态可以跨网络传输，从而在不同服务器间共享会话。
    //兼容性：序列化确保了不同版本的软件之间可以互相读取和写入数据。
//● Java对象序列化
    //代码举例
    import java.io.*;

    // SessionData类实现了Serializable接口，使其对象可以被序列化和反序列化
    public class SessionData implements Serializable {
        // serialVersionUID是序列化版本号，用于验证序列化的兼容性
        private static final long serialVersionUID = 1L;

        // 用户名字段，将会被序列化
        private String username;

        // 密码字段，使用transient关键字标记，表示不参与序列化过程
        private transient String password;

        // 省略了构造函数、getter和setter方法，这些方法用于创建对象和访问私有字段

        public static void main(String[] args) {
            // 创建一个SessionData实例，并设置用户名和密码
            SessionData sessionData = new SessionData("user", "pass");

            // 序列化过程
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("session.ser"))) {
                // 使用ObjectOutputStream将sessionData对象写入到文件session.ser中
                out.writeObject(sessionData);
            } catch (IOException e) {
                // 捕获并打印可能发生的I/O异常
                e.printStackTrace();
            }

            // 反序列化过程
            try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("session.ser"))) {
                // 使用ObjectInputStream从文件session.ser中读取对象，并将其转型为SessionData类型
                SessionData deserializedData = (SessionData) in.readObject();
                // 输出反序列化后的用户名
                System.out.println(deserializedData.getUsername()); // 输出：user
                // 由于password字段被标记为transient，它不会被序列化，因此反序列化后的值为null
            } catch (IOException e) {
                // 捕获并打印可能发生的I/O异常
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                // 捕获并打印可能发生的类未找到异常，这种情况通常发生在反序列化过程中
                e.printStackTrace();
            }
        }
    }


//● 自定义序列化策略
    //使用Externalizable接口:
public class SessionData implements Externalizable {
    // 类定义和成员变量

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        // 自定义序列化逻辑
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        // 自定义反序列化逻辑
    }
}

}
