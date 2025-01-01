<?php
session_start();
require_once('LineLogin.php');
require_once('db_connect.php');  // เชื่อมต่อฐานข้อมูล

if (!isset($_SESSION['profile'])) {
    header("location: index.php");
    exit();
} 

// ดึงข้อมูลจาก session
$profile = $_SESSION['profile'];
var_dump($profile);

// ดึงข้อมูลผู้ใช้จากฐานข้อมูลโดยใช้ email จาก profile
$stmt = $conn->prepare("SELECT id, name, email, picture, role FROM users WHERE email = :email");
$stmt->bindParam(':email', $profile->email);
$stmt->execute();
$userData = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$userData) {
    die("User not found in the database.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Line Login</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
</head>
<body>

    <?php require_once("nav.php"); ?>    

    <main class="container">
        <div class="bg-light p-5 rounded">
            <h1>Welcome, <?php echo htmlspecialchars($userData['name']); ?></h1>
            <p class="lead">Your email: <?php echo htmlspecialchars($userData['email']); ?></p>
            <p>Your role: <?php echo htmlspecialchars($userData['role']); ?></p>
            <img src="<?php echo htmlspecialchars($userData['picture']); ?>" class="rounded" alt="profile img">
        </div>
    </main>

</body>
</html>
