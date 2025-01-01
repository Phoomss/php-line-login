<?php
include_once 'db_connect.php';
class LineLogin
{
    #### change your id
    private const CLIENT_ID = '2006730624';
    private const CLIENT_SECRET = 'df75c4ae7f6cf084fd04cbae845c0386';
    private const REDIRECT_URL = 'http://127.0.0.1/php-line-login/callback.php';

    private const AUTH_URL = 'https://access.line.me/oauth2/v2.1/authorize';
    private const PROFILE_URL = 'https://api.line.me/v2/profile';
    private const TOKEN_URL = 'https://api.line.me/oauth2/v2.1/token';
    private const REVOKE_URL = 'https://api.line.me/oauth2/v2.1/revoke';
    private const VERIFYTOKEN_URL = 'https://api.line.me/oauth2/v2.1/verify';

    private function saveUser($profile)
    {
        global $conn;
    
        if (empty($profile->email)) {
            die('Email is required but not provided in profile.');
        }        
    
        // ตรวจสอบว่า profile->role มีค่าหรือไม่
        if (empty($profile->role)) {
            $profile->role = 'user'; // กำหนดค่า default ให้เป็น 'user'
        }
    
        // ตรวจสอบว่าผู้ใช้อยู่ในฐานข้อมูลแล้วหรือยัง
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->bindParam(':email', $profile->email);
        $stmt->execute();
    
        if ($stmt->rowCount() > 0) {
            // อัปเดตข้อมูลผู้ใช้
            $stmt = $conn->prepare("UPDATE users SET name = :name, picture = :picture, access_token = :access_token, refresh_token = :refresh_token, role = :role WHERE email = :email");
            $stmt->bindParam(':name', $profile->name);
            $stmt->bindParam(':picture', $profile->picture);
            $stmt->bindParam(':access_token', $profile->access_token);
            $stmt->bindParam(':refresh_token', $profile->refresh_token);
            $stmt->bindParam(':role', $profile->role);  // ใช้ :role ที่ถูกต้อง
            $stmt->bindParam(':email', $profile->email);
        } else {
            // เพิ่มผู้ใช้ใหม่
            $stmt = $conn->prepare("INSERT INTO users (name, email, picture, access_token, refresh_token, role) VALUES (:name, :email, :picture, :access_token, :refresh_token, :role)");
            $stmt->bindParam(':name', $profile->name);
            $stmt->bindParam(':email', $profile->email);
            $stmt->bindParam(':picture', $profile->picture);
            $stmt->bindParam(':access_token', $profile->access_token);
            $stmt->bindParam(':refresh_token', $profile->refresh_token);
            $stmt->bindParam(':role', $profile->role);  // ใช้ :role ที่ถูกต้อง
        }
    
        $stmt->execute();
    }    
    
    function getLink()
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        $_SESSION['state'] = hash('sha256', microtime(TRUE) . rand() . $_SERVER['REMOTE_ADDR']);

        $link = self::AUTH_URL . '?response_type=code&client_id=' . self::CLIENT_ID . '&redirect_uri=' . self::REDIRECT_URL . '&scope=profile%20openid%20email&state=' . $_SESSION['state'];
        return $link;
    }

    function refresh($token)
    {
        $header = ['Content-Type: application/x-www-form-urlencoded'];
        $data = [
            "grant_type" => "refresh_token",
            "refresh_token" => $token,
            "client_id" => self::CLIENT_ID,
            "client_secret" => self::CLIENT_SECRET
        ];

        $response = $this->sendCURL(self::TOKEN_URL, $header, 'POST', $data);
        return json_decode($response);
    }

    function token($code, $state)
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    
        if ($_SESSION['state'] != $state) {
            return false;
        }
    
        $header = ['Content-Type: application/x-www-form-urlencoded'];
        $data = [
            "grant_type" => "authorization_code",
            "code" => $code,
            "redirect_uri" => self::REDIRECT_URL,
            "client_id" => self::CLIENT_ID,
            "client_secret" => self::CLIENT_SECRET
        ];
    
        $response = $this->sendCURL(self::TOKEN_URL, $header, 'POST', $data);
        $token = json_decode($response);
    
        if (isset($token->id_token)) {
            $profile = $this->profileFormIdToken($token);
            $this->saveUser($profile); // บันทึกข้อมูลลงฐานข้อมูล
        }
    
        return $token;
    }    

    function profileFormIdToken($token = null)
    {
        $payload = explode('.', $token->id_token);
        $ret = array(
            'access_token' => $token->access_token,
            'refresh_token' => $token->refresh_token,
            'name' => '',
            'picture' => '',
            'email' => ''
        );

        if (count($payload) == 3) {
            $data = json_decode(base64_decode($payload[1]));
            if (isset($data->name))
                $ret['name'] = $data->name;

            if (isset($data->picture))
                $ret['picture'] = $data->picture;

            if (isset($data->email))
                $ret['email'] = $data->email;
        }
        return (object) $ret;
    }

    function profile($token)
    {
        $header = ['Authorization: Bearer ' . $token];
        $response = $this->sendCURL(self::PROFILE_URL, $header, 'GET');
        return json_decode($response);
    }

    function verify($token)
    {
        $url = self::VERIFYTOKEN_URL . '?access_token=' . $token;
        $response = $this->sendCURL($url, NULL, 'GET');
        return $response;
    }

    function revoke($token)
    {
        $header = ['Content-Type: application/x-www-form-urlencoded'];
        $data = [
            "access_token" => $token,
            "client_id" => self::CLIENT_ID,
            "client_secret" => self::CLIENT_SECRET
        ];
        $response = $this->sendCURL(self::REVOKE_URL, $header, 'POST', $data);
        return $response;
    }

    private function sendCURL($url, $header, $type, $data = NULL)
    {
        $request = curl_init();

        if ($header != NULL) {
            curl_setopt($request, CURLOPT_HTTPHEADER, $header);
        }

        curl_setopt($request, CURLOPT_URL, $url);
        curl_setopt($request, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($request, CURLOPT_SSL_VERIFYPEER, false);

        if (strtoupper($type) === 'POST') {
            curl_setopt($request, CURLOPT_POST, TRUE);
            curl_setopt($request, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        curl_setopt($request, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, 1);

        $response = curl_exec($request);
        return $response;
    }
}
