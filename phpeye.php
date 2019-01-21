<?php
require 'vendor/autoload.php';
use \SensioLabs\Security\SecurityChecker;

class phpeye {
    
    public $arrArgs = array("-p" => true,
                            "-f" => true,
                            "-v" => false,
                            "-h" => false);
    
    public $arrInput = array();
    
    public function __construct($argv) {
        // parse the command line args
        $this->parseArgs($argv);
        // first we check if the help was called
        if(isset($this->arrInput["-h"])) {
            $this->help();
            die();
        }
        // if theres a path that exists we can run
        if(isset($this->arrInput["-p"]) && is_dir($this->arrInput["-p"])) {
            $this->checkVersions();
            $this->checkSecurity();
        } else {
            $this->out("No path given. check -h");
        }
    }
    
    public function parseArgs($argv) {
        array_shift($argv);
        $open    = false;
        $fill    = false;
        if(count($argv) > 0) {
            foreach($argv as $commandSplit) {
                if($open && $fill) {
                    $this->arrInput[$fill] = $commandSplit;
                    $open = false;
                    $fill = false;
                }
                if(!$open && isset($this->arrArgs[$commandSplit])) {
                    if($this->arrArgs[$commandSplit] == true) {
                        $fill = $commandSplit;
                        $open = true;
                    } else {
                        $this->arrInput[$commandSplit] = true;
                    }
                }
            }
        }
    }
    
    public function checkVersions() {
        // first we check the version differences
        $command = 'composer show --latest -d "' . $this->arrInput["-p"] . '" --format=json';
        $ret = $this->exec($command);
        
        // parse json and check if valid data
        $json = json_decode($ret,true);
        if(!isset($json["installed"]) || count($json["installed"]) < 1) {
            $this->out("There seem to be no libs installed. Please verify and rerun phpeye\n");
        }

        // parse the composer json for later use
        $mainComposerJson      = json_decode(file_get_contents($this->arrInput["-p"] . "/composer.json"),true);
        $arrDirectDep          = array();
        foreach($mainComposerJson["require"] as $key => $val) {
            $arrDirectDep[$key] = true;
        }
        foreach($mainComposerJson["require-dev"] as $key => $val) {
            $arrDirectDep[$key] = true;
        }
        
        // prepare storage array
        $arrVer = array("semver-safe-update" => array(), "update-possible" => array());
        
        // store the necessary info in the arrVer
        foreach($json["installed"] as $entry) {
            $arrVer[$entry["latest-status"]][] = array("name"  => $entry["name"],
                                                       "currv" => $entry["version"],
                                                       "latv"  => $entry["latest"]);
        }
        
        if(count($arrVer) > 0) {
            $this->out("Listing outdated libs:\n-----------------------------------------");
            $this->out("+ Major update available");
            foreach($arrVer["update-possible"] as $ver) {
                if(isset($arrDirectDep[$ver["name"]]) || isset($this->arrInput["-v"])) {
                    $this->out(" - " . $ver["name"] . " | Current Version: " . $ver["currv"] . " | Latest Version: " . $ver["latv"]);
                }
            }
            $this->out("\n-----------------------------------------\n+ Minor update available");
            foreach($arrVer["semver-safe-update"] as $ver) {
                if(isset($arrDirectDep[$ver["name"]]) || isset($this->arrInput["-v"])) {
                    $this->out(" - " . $ver["name"] . " | Current Version: " . $ver["currv"] . " | Latest Version: " . $ver["latv"]);
                }
            }
        } else {
            $this->out("All libs are up to date!");
        }
    }
    
    public function checkSecurity() {
        // first we add our direct composer file
        $fullDirectPath = $this->arrInput["-p"] . "/composer.lock";
        $arrSecurity    = array();
        
        // first we check our main composer.lock
        $ret = $this->parseSecurityResults($this->arrInput["-p"] . "/composer.lock");
        if($ret) {
            $arrSecurity[$this->arrInput["-p"] . "composer.lock"] = $ret;
        }
        
        // now we need to find the vendor library composer jsons, lets abuse find for this
        $composerFiles = $this->exec("find " . $this->arrInput["-p"] . "/vendor/ -iname composer.lock");
        foreach(explode("\n",$composerFiles) as $composerFile) {
            if(trim($composerFile) != "") {
                $ret = $this->parseSecurityResults($composerFile);
                if($ret) {
                    $arrSecurity[$composerFile] = $ret;
                }
            }
        }
        

        if(count($arrSecurity) > 0) {
            $this->out("\nListing security relevant info:\n-----------------------------------------");
            foreach($arrSecurity as $key => $arrSec) {
                $this->out("> " . $key);
                foreach($arrSec as $sec) {
                    $this->out(" + " . $sec["name"] . " | Version: " . $sec["version"]);
                    foreach($sec["vulns"] as $vuln) {
                        $this->out("  - " . $vuln["title"] . " | " . $vuln["cve"] . " | " . $vuln["link"]);
                    }
                }
            }
        } else {
            $this->out("No security problems found. congratz!");
        }
    }
    
    public function parseSecurityResults($path) {
        $arrSec = array();
        // init it and run for the given path
        $checker = new SecurityChecker();
        $result  = $checker->check($path , 'json');
        $alerts  = json_decode((string) $result, true);
        if(count($alerts) > 0) {
            foreach($alerts as $key => $alert) {
                $arrSec[] = array("name"    => $key,
                                  "version" => $alert["version"],
                                  "vulns"   => $alert["advisories"]);
            }
            return $arrSec;
        }
        return false;
    }

    public function out($text) {
        echo $text . "\n";
    }
    
    public function exec($command) {
        ob_start();
        passthru($command);
        $ret = ob_get_contents();
        ob_end_clean(); //Use this instead of ob_flush()
        return $ret;
    }
    
    public function help()  {
        $this->out("|PHPeye-tool help:");
        $this->out("");
        $this->out("Param       Description");
        $this->out(" -p <path>  Path to the directory including the composer.json / composer.lock (no ending slash) /path/to/something");
        $this->out(" -v         Print verbose output (includes outdated versions of libraries depended second level)");
        $this->out("");
        $this->out("So long and thanks for all the fish");
    }
    
}







$t = new phpeye($argv);

?>