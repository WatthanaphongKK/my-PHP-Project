<?php
    session_start(); //ประกาศ session start
    require_once 'config/db.php';

    if (isset($_POST['signup'])){
        $firstname=$_POST['firstname'];
        $lastname=$_POST['lastname'];
        $email=$_POST['email'];
        $password=$_POST['password'];
        $c_password=$_POST['c_password'];
        $urole='user';

        if (empty($firstname)){
            $_SESSION['error'] = 'กรุณากรอกชื่อ';
            header("location: index.php");
        }elseif (empty($lastname)){
            $_SESSION['error'] = 'กรุณากรอกนามสกุล';
            header("location: index.php");
        }elseif (empty($email)){
            $_SESSION['error'] = 'กรุณากรอกอีเมล';
            header("location: index.php");
        }elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)){ //ตรวจสอบรูปแบบอีเมล
            $_SESSION['error'] = 'รูปแบบอีเมลไม่ถูกต้อง';
            header("location: index.php");
        }elseif (empty($password)){
            $_SESSION['error'] = 'กรุณากรอกรหัสผ่าน';
            header("location: index.php");
        }elseif (strlen($_POST['password'])>20||strlen($_POST['password'])<5){ //ตรวจสอบรูปแบบอีเมล
            $_SESSION['error'] = 'รหัสผ่านต้องมีความยาวระหว่าง 5 ถึง 20 ตัวอักษร';
            header("location: index.php");
        }elseif (empty($c_password)){
            $_SESSION['error'] = 'กรุณายืนยันรหัสผ่าน';
            header("location: index.php");
        }elseif ($password !== $c_password){
            $_SESSION['error'] = 'รหัสผ่านไม่ตรงกัน';
            header("location: index.php");
        }else {
            try{
                //ตัวแปล conn มาจากไฟล์ของฐานข้อมูล 
                $check_email = $conn->prepare("SELECT email FROM user WHERE email = :email"); //ใส่ semi-colon แทน $ เพื่อป้องกัน
                $check_email->bindParam(":email", $email);
                $check_email->execute();
                $row = $check_email->fetch(PDO::FETCH_ASSOC); //ทำการเพิ่มค่าลงใน row
                //กำหนดเงื่อนไขเพื่อตรวจสอบความถูกต้องของ input 
                if ($row['email']==$email){
                    $_SESSION['warning'] = "มีอีเมลนี้ในระบบแล้ว <a href ='signin.php'>คลิ๊กที่นี่</a>เพื่อเข้าสู่ระบบ";
                    header("location: index.php");
                }elseif (!isset($_SESSION['error'])) {
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $conn -> prepare("INSERT INTO user(firstname, lastname, email, password, urole) VALUES(:firstname, :lastname, :email, :password, :urole)");
                    $stmt->bindParam(":firstname", $firstname);
                    $stmt->bindParam(":lastname", $lastname);
                    $stmt->bindParam(":email", $email);
                    $stmt->bindParam(":password", $passwordHash);
                    $stmt->bindParam(":urole", $urole);
                    $stmt->execute(); //หลังจากใช้คำสั่ง inssert, bindParam ต้องตามด้วย execute
                    $_SESSION['success']="สมัครสมาชิกเรียบร้อย! <a href='signin.php' class='alert-link'>คลิ๊กที่นี่</a>เพื่อเข้าสู่ระบบ";
                    header("location: index.php");
                }else{
                    $_SESSION['error']="มีบางอย่างผิดพลาด";
                    header("location: index.php");
                }

            }catch(PDOException $e){
                echo $e->getMessage();
            }
        }
    }
?>
