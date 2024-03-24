rule PHP_WebShell_C99Variant {
    meta:
        description = "Detects C99 PHP Web Shell Variant"
        reference = "Derived from analysis of provided PHP script"
    
    strings:
        $spyhackerz = "spyhackerz.net/save.php" ascii wide
        $eval = "eval" ascii wide
        $iframe = "<iframe style='height: 0; width:0;'" ascii wide
        $script_src = "<SCRIPT SRC=" ascii wide
        $base64_decode = "base64_decode" ascii wide
        $gzinflate_base64_decode = "gzinflate(base64_decode(" ascii wide
        $file_get_contents = "file_get_contents" ascii wide
        $curl_init = "curl_init(" ascii wide
        $script_end = "</SCRIPT>" ascii wide

    condition:
        any of them
}
