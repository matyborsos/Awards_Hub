<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" type="text/css" href="style.css">
    <title>Awards</title>
    <style>
        table {
        margin: 0 auto;
        font-size: large;
        border: 1px solid transparent;
        background-color: #5c2626;
        }

        td {
        border: 1px solid transparent;
        margin: 10px;
        color: #d8c690;
        font-weight: lighter;
        padding: 10px;
        text-align: center;
        }

        th {
        font-weight: bold;
        border: 1px solid black;
        color: #cbb26a;
        padding: 10px;
        text-align: center;
        margin: 10px;
        }
    </style>
</head>
<body>
    <div class="topnav" style="background-color: #5c2626; height: 12%;">
        <a href="imprintpage.html" style="margin-left: 70px;">Songs from the genre you selected:</a>
    </div>
    <ul style="left: 0; top: 0;">
        <li><img src="img/Logo.png"></li>
        <li><a href="index.html">Home</a></li>
        <li><a href="awards.html">Awards</a></li>
        <li><a href="music.html">Music</a></li>
        <li><a href="artists.html">Artists</a></li>
		<li><a href="login.php">Maintanance Page</a></li>
    </ul>
    <?php   
        $servername = "localhost";
        $username = "mborsos";
        $password = "y0WmsG";
        $dbname = "Group-11";
        
        // Create connection
        $conn = new mysqli($servername, $username, $password, $dbname);
        // Check connection
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }
        
        $genre = $_POST["genre"];
        
        $sql = "SELECT song_id, song_title, genre, language, version FROM Song JOIN Music ON song_id = music_id WHERE upper(genre) = upper('$genre') ORDER BY song_id DESC;";
        $result = $conn->query($sql);
    ?>
    <h2 style="padding-left: 260px; padding-right: 200px; padding-top: 150px">
    Here is a list of songs of the genre you chose:
	</h2>
    <section style="padding-top: 50px; padding-left: 200px; padding-right: 20px">
        <table style="width:80%">
        <tr>
        <th>Song Title</th>
        </tr>
        <?php 
        if ($result->num_rows <= 0) {
            ?>
            <tr>
            <td><?php echo "No results!";?></td>
            </tr>
            <?php
        }
        else {    
        while($rows=$result->fetch_assoc())
            {
            ?>
            <tr>
            <td><?php echo "<a style='color:white;' href='Song.php?song_id=".$rows['song_id']."'>".$rows['song_title']."</a>";?></td>
            </tr>
            <?php
            }
        }
        ?>
        </table>
    </section>
</body>
</html>