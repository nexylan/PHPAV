<?php

ini_set('memory_limit','512M');

/*
    This file is part of PHPAV.

    PHPAV is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
    PHPAV is coded and maintained by Gaetan ALLART.
	
    © Gaetan ALLART 2014
	
    http://www.nexylan.com/
*/

include (dirname(__FILE__).'/lib/color.class.php');
// We are Gentoo users, we love color in bash shell :)
$colors = new Colors();	


// Detect more than 10000 consecutive characters on first line
function detect_obfuscated($filecontent) {
	$weirdlength = 10000;
	if (isset($filecontent[0]) && strlen($filecontent[0]) > $weirdlength && preg_match("/[A-Za-z0-9\\\]{$weirdlength}/",$filecontent[0])) { // If a line contains more than 10,000 characters, write it to stdout
		return true;
	}
	return false;
}

// Detect eval functions on first line
function detect_onelineshell($filecontent) {
	if (isset($filecontent[0]) && preg_match("/eval\(/",$filecontent[0])) {
		return true;
	}
	return false;
}

// Detect php files in upload folder
function detect_upload($filename) {
	if (preg_match("#/wp-content/uploads#",$filename)) {
		return true;
	}
	return false;
}

// Detect webshells patterns
function detect_shell($filecontent) {
	global $shells;

	foreach ($shells as $shell) {
		if (strpos(implode($filecontent),$shell)) {
			return true;
		}
	}
	return false;
}

function report_file($file,$reason) {
	global $colors;

	echo $colors->getColoredString("Infected file (reason : $reason) :\n","red");
    echo $colors->getColoredString("\t$file\n","light_blue");
}

function delete_file($file,$content,$confirmation) {
    global $colors;

    echo $colors->getColoredString("This file ($file) containing the following code :\n","cyan");
    echo "\t".$content."\n";

    if ($confirmation) {
        echo $colors->getColoredString("Delete ? (y/n)","cyan");
        $input = fgetc(STDIN);

        if ($input == 'y')
        {
            unlink($file);
        }
        else {
            echo "$input";
        }
    }
    else {
        unlink ($file);
    }
}

function patch_file($file,$content) {
    $newfile = preg_replace("/^.*<\?php/","<?php",$content);
    $fp = fopen("$file.fixed", 'w');
    fwrite ($fp,$newfile);
    for ($i=1;$i<sizeof($content)) {
        fwrite($fp,$content[$i]);
    }
    exec("diff -u $file $file.fixed > fix.patch");

    $diff = file("fix.patch");
    echo "I'm proposing the following patch. What do you think ?";
    echo implode($diff);
}


// Main(void)
if (empty($argv[1])) die("Usage: php find.php directory_to_scan > infected.txt\n");
else {
	echo $colors->getColoredString("Scanning " . $argv[1] . " for potential obfuscated malware...\n\n","green");
	$data = array();
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($argv[1]),RecursiveIteratorIterator::SELF_FIRST); // Grab array of the entire structures of $argv[1] (a directory)
        $c = 0; // Counter for files processed
        $f = 0; // Counter for files with potential malware

        // Preload data
        $shells = file(dirname(__FILE__).'/data/webshells.txt');

        foreach ($files as $file)
        {
                //if (($c % 10000) == 0 && $c > 0) { // Display status for every 10,000 files
                	//echo $colors->getColoredString("Processed " . $c . " files, found " . $f . "\n","purple");
                //}
                if (is_dir($file) === true) // Not in use, was used to check directory traversal was working properly
                {
                        //echo "Traversing into " . strval($file);
                }
                else { // If is file
                        if (preg_match("/\.php$/",$file)) { // Currently only selects PHP scripts for scanning
                                $arr = file($file); // Puts each line of the file into an array element
                                if (detect_obfuscated($arr)) {
                                    report_file($file,"obfuscated code on first line");
                                    $f++;
                                }
                                if(detect_onelineshell($arr)) {
                                    report_file($file,"First-line file with eval");
                                    if (sizeof($arr) == 1) {
                                        delete_file($file,implode($arr),false);
                                    }
                                    else {
                                        patch_file($file,$arr);
                                    }
                                    $f++;
                                }
                                if (detect_upload ($file)) {
                                    report_file($file,"PHP file in wordpress upload dir");
                                    $f++;
                                }
                                if (detect_shell($arr)) {
                                    report_file($file,"Shell script pattern");
                                	$f++;
                                }
                            }
                        }
                        $c++;
                    }
                }

                ?>