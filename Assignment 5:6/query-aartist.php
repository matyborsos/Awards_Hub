<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" type="text/css" href="style.css">
<title>Awards</title>
<style>
table {
margin: 0 auto;
font-size: large;
border: 1px solid black;
}


h1 {
text-align: center;
color: #c18f59;
font-size: xx-large;
font-weight: bold;
padding: 30px;
}


td {
border: 1px solid black;
margin: 10px;
}


th,
td {
font-weight: bold;
border: 1px solid black;
padding: 10px;
text-align: center;
margin: 10px;
}


td {
font-weight: lighter;
}
</style>
</head>
<body>
<div class="topnav" style="background-color: #5c2626; height: 12%;">
<a href="imprintpage.html" style="margin-left: 70px;">Input Feedback Page</a>
</div>
<ul style="left: 0; top: 0;">
<li><img src="img/Logo.png"></li>
<li><a href="index.html">Home</a></li>
<li><a href="awards.html">Awards</a></li>
<li><a href="music.html">Music</a></li>
<li><a href="artists.html">Artists</a></li>
		<li><a href="login.php">Maintanance Page</a></li>
</ul>
<h1 style="padding-top: 170px; padding-left: 200px;"> Succesfully added! <h1>
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$servername = "localhost";
$username = "mborsos";
$password = "y0WmsG";
$dbname = "Group-11";


$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
die("Connection failed: " . $conn->connect_error);
}


$id = rand(1000, 1999);


$sql1 = "INSERT INTO Award (award_id, year) VALUES (?, ?)";
$stmt1 = $conn->prepare($sql1);
$stmt1->bind_param("si", $id, $_POST["year"]);

if ($stmt1->execute()) {
    $stmt1->close();

    $sql2 = "INSERT INTO Artist_Award (award_id, artist_title, winner_artist) VALUES (?, ?, ?)";
    $stmt2 = $conn->prepare($sql2);
    $stmt2->bind_param("sss", $id, $_POST["artist_title"], $_POST["winner_artist"]);
        
        if ($stmt2->execute()) {
    
        } else {
            echo "Error: " . $stmt2->error;
        }

    $stmt2->close();
} else {
    echo "Error: " . $stmt1->error;
}

// Now retrieve and display the results
$sql = "SELECT * FROM Artist_Award JOIN Award ON Artist_Award.award_id = Award.award_id";
$result = $conn->query($sql);


if ($result->num_rows > 0) {
?>
<section style="padding-top: 30px; padding-left: 200px; padding-right: 20px">
<table style="width:80%">
<tr>
<th>Winner Artist</th>
<th>Artist Prize</th>
<th>Year</th>
</tr>
<?php
while ($rows = $result->fetch_assoc()) {
?>
<tr>
<td><?php echo $rows['winner_artist'];?></td>
<td><?php echo $rows['artist_title'];?></td>
<td><?php echo $rows['year'];?></td>
</tr>
<?php
}
?>
</table>
</section>
<?php
}


$conn->close();
?>
<div style="padding-left: 800px">
    <button type="button"><a href="input.php">Go back!</a></button>
</div>
</body>
</html>