#!/usr/bin/perl
# Wordpress Detector
# Coded By : DR-IMAN ( Telegram : @DarkCod3r )
# List Of Wordpress Vulnerabilities

use Term::ANSIColor;

use LWP::UserAgent;

use HTTP::Request::Common qw(GET);

use WWW::Mechanize;  

use Socket;

$mech = WWW::Mechanize->new(autocheck => 0);
$ag = LWP::UserAgent->new();

$ag->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801");

$ag->timeout(10);

sub getSites {
	for($count=10;$count<=1000;$count+=10)
	{
		$k++;
#		$url = "http://www.hotbot.com/search/web?pn=$k&q=ip%3A$ip&keyvol=01f9093871a6d24c0d94";
		$url = "https://www.bing.com/search?q=ip%3a$ip&go=Submit+Query&qs=ds&first=$count&FORM=PERE$k";
#		$url = "https://www.bing.com/search?q=ip%3A$ip+&count=50&first=$count";
		$resp = $ag->request(HTTP::Request->new(GET => $url));

		$rrs = $resp->content;



		while($rrs =~ m/<a href=\"?http:\/\/(.*?)\//g)
		{
	
			$link = $1;
		
			if ( $link !~ /overture|msn|live|bing|yahoo|duckduckgo|google|yahoo|microsof/)
			{
				if ($link !~ /^http:/)
				{
					$link = 'http://' . "$link" . '/';
				}
	
				if($link !~ /\"|\?|\=|index\.php/)
				{
					if  (!  grep (/$link/,@result))
					{
						push(@result,$link);
					}
				}
			} 
		}
	}
	$found = $#result + 1;
	print "found $found sites\n";
	
}


sub WPS {
	foreach $site (@result)
	{
		$url = $mech->get("$site");
		$Scont = $mech->content;
		if ($Scont =~ m/<meta name="generator" content="WordPress 4.7.2/ig)
		{
			$license = $site."license.txt";
			$horse = $mech->get("$license");
			if ($horse->is_success)
			{
				$Scont = $mech->content;
				$login = $site."wp-login.php";
				$logUrl = $mech->get("$login");
	 	                if ($Scont =~ m/ver=4.7.2/)     
				{
					push @WPS,$site;
					print "$site\n";
				}
				elsif($logUrl->is_success) 
				{
					push @WPS,$site; 
					print "$site\n";
				}

			}

		}


	}

}


sub WPS1 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 4.7.1/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=4.7.1/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}


sub WPS2 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 4.7/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=4.7/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}


sub WPS3 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 3.6/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=3.6/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}


sub WPS4 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 4.7.4/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=4.7.4/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}


sub WPS5 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 3.6.9/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=3.6.9/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}


sub WPS6 {
	foreach $site (@result)
	{
		if  (!  grep (/$site/,@WPS))
		{
			$url = $mech->get("$site");
			$Scont = $mech->content;
			if ($Scont =~ m/<meta name="generator" content="WordPress 3.4/ig)
			{
				push @JM,$site;
				print "$site\n";
			}
			else 
			{
				$admin = "$site/wp-login.php";
				$mech->get("$site");
				$AdminCont = $mech->content;
				if ($AdminCont =~ m/ver=3.4/ig)
				{
					push @JM,$site;
					print "$site\n";
				}
			}
		}
	}
}

sub vuln {

print" Wordpress Version $input \n";

}


sub IP_id {
	print "Enter The Ip of Server or Site Link\n";
	print ">> ";
	$input =<stdin>;
	chomp($input);
	if ($input =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
	{
		$ip = $input;
		print "Pleast wait ... Getting WebSites...\n";
		getSites();
	}
	elsif ($input =~ m/\D/g)
	{
		if ($input =~ m/https:\/\//)
		{
			$source = substr($input,8,length($input));
			print "Site : $source\n";
			print "Getting IP Adress...\n";
                        $ip = inet_ntoa(inet_aton($source));
                        print "IP: $ip\n";
			print "Pleast wait ... Getting WebSites...\n";
			getSites();
		}
                elsif ($input =~ m/http:\/\//)
                {
                        $source = substr($input,7,length($input));
                        print "Site : $source\n";
			print "Getting IP Adress...\n";
                        $ip = inet_ntoa(inet_aton($source));
                        print "IP: $ip\n";
			print "Pleast wait ... Getting WebSites ...\n";
			getSites();

                }
		else 
		{
			print "Site : $input\n";
			print "Getting IP Adress...\n";
			$ip = inet_ntoa(inet_aton($input));
			print "IP : $ip\n";
			print "Pleast wait ... Getting WebSites...\n";
			getSites();
		}
	}	
}
system(($^O eq 'MSWin32') ? 'cls' : 'clear');
sub Into {
print"\n";
print colored ("                           >> Coded By DR-IMAN << ",'bold yellow'),"\n";
	print qq(                         
                                          ,,                                            
`7MMF'     A     `7MF'                  `7MM                                            
  `MA     ,MA     ,V                      MM                                            
   VM:   ,VVM:   ,V ,pW"Wq.`7Mb,od8  ,M""bMM `7MMpdMAo.`7Mb,od8 .gP"Ya  ,pP"Ybd ,pP"Ybd 
    MM.  M' MM.  M'6W'   `Wb MM' "',AP    MM   MM   `Wb  MM' "',M'   Yb 8I   `" 8I   `" 
    `MM A'  `MM A' 8M     M8 MM    8MI    MM   MM    M8  MM    8M"""""" `YMMMa. `YMMMa. 
     :MM;    :MM;  YA.   ,A9 MM    `Mb    MM   MM   ,AP  MM    YM.    , L.   I8 L.   I8 
      VF      VF    `Ybmd9'.JMML.   `Wbmd"MML. MMbmmd' .JMML.   `Mbmmd' M9mmmP' M9mmmP' 
                                               MM                                       
                                             .JMML.                                     
                                                                                        
                                                                                        
`7MM"""Yb.             mm                     mm                                        
  MM    `Yb.           MM                     MM                                        
  MM     `Mb  .gP"Ya mmMMmm .gP"Ya   ,p6"bo mmMMmm ,pW"Wq.`7Mb,od8                      
  MM      MM ,M'   Yb  MM  ,M'   Yb 6M'  OO   MM  6W'   `Wb MM' "'                      
  MM     ,MP 8M""""""  MM  8M"""""" 8M        MM  8M     M8 MM                          
  MM    ,dP' YM.    ,  MM  YM.    , YM.    ,  MM  YA.   ,A9 MM                          
.JMMmmmdP'    `Mbmmd'  `Mbmo`Mbmmd'  YMbmd'   `Mbmo`Ybmd9'.JMML.    
                    																 
);		
#Just Type Name.For Example : WPS or WPS1
    print " 
	Choice Method: 1-WPS(4.7.2) , 2-WPS1(4.7.1) , 3-WPS2(4.7) , 4-WPS3(3.6),";
	print "\n
	5-WPS4(4.7.4) , 6-WPS5(3.6.9) , 7-WPS6(3.4) , 8-List of Wordpress Vulnerabilities(vuln)  :";
	$choice1 = <stdin>;						
	chomp ($choice1);
	if ($choice1 eq "WPS" or $choice1 eq "wps" or $choice1 eq "" or $choice1 eq "Wps" or $choice1 eq "1")
	{
		print "\nExtract Wordpress  4.7.2  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress sites\n";
		WPS();
		$n_found = $#WPS;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS.txt");
			map {$_ = "$_\n"} (@WPS);
			print wp @WPS;
		print "\t>> Saved at WPS.txt\n";
		}
	}
	
	elsif ($choice1 eq "WPS1" or $choice1 eq "wps1" or $choice1 eq "" or $choice1 eq "Wps1" or $choice1 eq "2") 
	{
		print "\nExtract Wordpress  4.7.1  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress sites\n";
		WPS();
		$n_found = $#WPS1;
		print "\t>> Found $n_found Wordpress(4.7.1) sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS1.txt");
			map {$_ = "$_\n"} (@WPS1);
			print wp @WPS1;
		print "\t>> Saved at WPS1.txt\n";
		}
	}
	
		elsif ($choice1 eq "WPS2" or $choice1 eq "wps2" or $choice1 eq "" or $choice1 eq "Wps2" or $choice1 eq "3") 
	{
		print "\nExtract Wordpress  4.7  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress(4.7) sites\n";
		WPS();
		$n_found = $#WPS2;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS2.txt");
			map {$_ = "$_\n"} (@WPS2);
			print wp @WPS2;
		print "\t>> Saved at WPS2.txt\n";
		}
	}

		elsif ($choice1 eq "WPS3" or $choice1 eq "wps3" or $choice1 eq "" or $choice1 eq "Wps3" or $choice1 eq "4" ) 
	{
		print "\nExtract Wordpress  3.6  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress(3.6) sites\n";
		WPS();
		$n_found = $#WPS3;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS3.txt");
			map {$_ = "$_\n"} (@WPS3);
			print wp @WPS3;
		print "\t>> Saved at WPS3.txt\n";
		}
	}
	
		elsif ($choice1 eq "WPS4" or $choice1 eq "wps4" or $choice1 eq "" or $choice1 eq "Wps4" or $choice1 eq "5" ) 
	{
		print "\nExtract Wordpress  4.7.4  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress(4.7.4) sites\n";
		WPS();
		$n_found = $#WPS4;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS4.txt");
			map {$_ = "$_\n"} (@WPS4);
			print wp @WPS4;
		print "\t>> Saved at WPS4.txt\n";
		}
	}
	
		elsif ($choice1 eq "WPS5" or $choice1 eq "wps5" or $choice1 eq "" or $choice1 eq "Wps5" or $choice1 eq "6" ) 
	{
		print "\nExtract Wordpress  3.6.9  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress(3.6.9) sites\n";
		WPS();
		$n_found = $#WPS5;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS5.txt");
			map {$_ = "$_\n"} (@WPS5);
			print wp @WPS5;
		print "\t>> Saved at WPS5.txt\n";
		}
	}
	
		elsif ($choice1 eq "WPS6" or $choice1 eq "wps6" or $choice1 eq "" or $choice1 eq "Wps6" or $choice1 eq "7" )
	{
		print "\nExtract Wordpress  3.4  sites...\n";
		print "==============================\n";
		IP_id();
		print "Searching for Wordpress(3.4) sites\n";
		WPS();
		$n_found = $#WPS6;
		print "\t>> Found $n_found Wordpress sites\n\n";
		print "Do you want to save the result (Y\\n): ";
		$save = <stdin>;
		chomp($save);
		if ($save eq "Y" or $save eq "" or $save eq "y")
		{
			open(wp, ">WPS6.txt");
			map {$_ = "$_\n"} (@WPS6);
			print wp @WPS6;
		print "\t>> Saved at WPS6.txt\n";
		}
	}
	
     
	    elsif ($choice1 eq "vuln" or $choice1 eq "Vuln" or $choice1 eq "" or $choice1 eq "VULN" or $choice1 eq "8" )
	{
	
	print "\nChoice Version : ( 3.4 , 3.6 , 3.6.9 , 4.7 , 4.7.1 , 4.7.2 , 4.7.4 ) :  ";
	$choice1 = <stdin>;						
	chomp ($choice1);
	
 if ($choice1 eq "4.7" )
  {
 print" 
\nWordpress 4.7 Vulnerabilities \n
Version 4.7 : \n
1-Reset API (CVE Details https://goo.gl/pBsQHh ) \n
2-bypass intended access restrictions (CVE Details  https://goo.gl/6Cch8F ) \n
3-widget-editing accessibility-mode feature CSRF (CVE Details  https://goo.gl/tHa24Y ) \n
4-wp-mail.php bypass intended posting restrictions (CVE Details  https://goo.gl/De7xfy ) \n
5-theme-name fallback functionality in wp-includes/class-wp-theme.php Xss (CVE Details  https://goo.gl/ctebN4 ) \n
6-remote hijack the authentication of unspecified victims (CVE Details  https://goo.gl/eqjw7V ) \n
7-Multiple cross-site scripting (XSS) vulnerabilities (CVE Details  https://goo.gl/6B2Zwr ) \n
8-REST API implementation (CVE Details  https://goo.gl/hLY2PT ) \n ";
  }
  
  elsif ($choice1 eq "4.7.1" )
  {
 print"
\nWordpress 4.7.1 Vulnerabilities \n
Version 4.7.1 : \n
1-REST API (CVE Details https://goo.gl/5ThgVN ) \n
2-Cross-site scripting (XSS) Vulnerability (CVE Details https://goo.gl/b18rKH) \n
3-SQL injection vulnerability in wp-includes/class-wp-query.php (CVE Details https://goo.gl/r298U7 ) \n
4-bypass intended access restrictions (CVE Details https://goo.gl/Vr75rt ) \n ";
 }
 elsif ($choice1 eq "4.7.2" )
  { 
 print"
\nWordpress 4.7.2 Vulnerabilities \n
Version 4.7.2 : \n
1-REST API (CVE Details https://goo.gl/z8VHBM ) \n
2-CSRF in wp-admin/includes/class-wp-press-this.php (CVE Details https://goo.gl/rgshdK ) \n
3-Xss in wp-admin/js/tags-box.js (CVE Details https://goo.gl/59S9JU ) \n
4-Xss in wp-includes/embed.php (CVE Details https://goo.gl/mM7KLX ) \n
5- files can be deleted by administrators (CVE Details https://goo.gl/fYR2Rs ) \n
6-Redirect URL in wp-includes/pluggable.php (CVE Details https://goo.gl/6jB7Vw ) \n
7-Xss in wp-includes/media.php (CVE Details https://goo.gl/vSRGsV ) \n";
 }
 elsif ($choice1 eq "4.7.4" )
   {
 print
"\nWordpress 4.7.4 Vulnerabilities \n
1-redirect validation in the HTTP class (CVE Details https://goo.gl/V6RtWV ) \n
2-lack of capability checks for post meta data in the XML-RPC API (CVE Details https://goo.gl/65L65N ) \n
3-Cross Site Request Forgery (CVE Details https://goo.gl/xnYB5J ) \n
4-cross-site scripting (CVE Details https://goo.gl/R1wfLp ) \n
5-improper handling of post meta data values in the XML-RPC API (CVE Details https://goo.gl/jY5ZV6  ) \n
6-cross-site scripting (CVE Details https://goo.gl/q7aqh4  ) \n
7-Host HTTP header for a password-reset e-mail message (CVE Details https://goo.gl/KpYMKr ) \n";
  }
  elsif ($choice1 eq "3.6" )
   {
 print" 
\nWordpress 3.6 Vulnerabilities \n
1-denial of service (CPU consumption) via a large document (CVE Details https://goo.gl/sPLZg6 ) \n
2-denial of service (memory and CPU consumption) via a crafted XML document (CVE Details https://goo.gl/uJ6Gf1 ) \n
3-inject arbitrary web script or HTML, and obtain Super Admin privileges (CVE Details https://goo.gl/1zt29y ) \n
4-obtain access via a forged cookie (CVE Details https://goo.gl/Hykwpa ) \n
5-remote authenticated users to publish posts by leveraging the Contributor role (CVE Details https://goo.gl/h6kcqo ) \n
6-remote authenticated users to conduct cross-site scripting (XSS) (CVE Details https://goo.gl/6EyKz3 ) \n
7-cross-site scripting (XSS) (CVE Details https://www.cvedetails.com/cve/CVE-2013-5738/ ) \n
8-remote authenticated users to spoof the authorship of a post (CVE Details https://goo.gl/ahiQTG ) \n
9-HTTP redirect (CVE Details https://goo.gl/bJFjVD ) \n
10-execute arbitrary code by triggering erroneous PHP unserialize operations (CVE Details https://goo.gl/X41fuS ) \n";
 }
 
 elsif ($choice1 eq "3.4" )
  {
 print"
\nWordpress 3.4 Vulnerabilities \n 
1-does not limit the number of elements in an XML document (CVE Details https://goo.gl/WCqhjE ) \n 
2-denial of service (memory and CPU consumption) (CVE Details https://goo.gl/nWD1Kv ) \n 
3-obtain access via a forged cookie (CVE Details https://goo.gl/2iF25x ) \n 
4-send HTTP requests to intranet servers (CVE Details https://goo.gl/L9hmd6 )\n 
5-remote authenticated users to bypass intended access (CVE Details https://goo.gl/jkbjXL ) \n 
6-Cross-site scripting (XSS) (CVE Details https://goo.gl/sDHWs7 ) \n";
}
 elsif ($choice1 eq "3.6.9" )
   {
 print"
\nWordpress 3.6.9 Vulnerabilities \n 
1-hijack the authentication of administrators (CVE Details https://goo.gl/ZC31nm ) \n 
2-bypass intended password-change restrictions  (CVE Details https://goo.gl/C9QntR ) \n 
3-obtain sensitive revision-history information to read a post (CVE Details https://goo.gl/bLeCm1 ) \n 
4-Open redirect vulnerability in the wp_validate_redirect function (CVE Details https://goo.gl/eZfcR3 ) \n 
5-Cross-site scripting (XSS) (CVE Details https://goo.gl/zMGSHa ) \n"; 
}



 }
 }
Into();