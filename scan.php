<?php

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
	if (isset($filecontent[0]) && strlen($filecontent[0]) > 10000 && preg_match("/[A-Za-z0-9]{10000}/",$filecontent[0])) { // If a line contains more than 10,000 characters, write it to stdout
		return true;
	}
	return false;
}

// Fetect eval functions on first line
function detect_onelineshell($filecontent) {
	if (isset($filecontent[0]) && preg_match("/eval\(/",$filecontent[0])) {
		return true;
	}
	return false;
}

// Main(void)
if (empty($argv[1])) die("Usage: php find.php directory_to_scan > infected.txt\n");
else {
        fwrite(STDERR, "Scanning " . $argv[1] . " for potential obfuscated malware...\n\n");
        $data = array();
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($argv[1]),RecursiveIteratorIterator::SELF_FIRST); // Grab array of the entire structures of $argv[1] (a directory)
        $c = 0; // Counter for files processed
        $f = 0; // Counter for files with potential malware
        foreach ($files as $file)
        {
                if (($c % 10000) == 0 && $c > 0) { // Display status for every 10,000 files
                        fwrite(STDERR, "Processed " . $c . " files, found " . $f . "\n");
                }
                if (is_dir($file) === true) // Not in use, was used to check directory traversal was working properly
                {
                        //echo "Traversing into " . strval($file);
                }
                else { // If is file
                        if (strpos($file, '.php') !== false || strpos($file, '.py') !== false || strpos($file, '.pl') !== false) { // Currently only selects PHP, Python and Perl scripts for scanning
                                $arr = file($file); // Puts each line of the file into an array element
								if (detect_obfuscated($arr) || detect_onelineshell($arr)) {
                                        echo $file . "\n";
                                        $f++;
                                }
                        }
                }
                $c++;
        }
}

?>