---
layout: post
title:  Defending WordPress from XML-RPC brute force attacks
date:   2014-09-15 00:08:00
categories: ModSecurity
---
Over the course of the last year a tremendous remote brute force (password guessing) attack campaign has been waged against web sites built with the popular blogging platform WordPress. Until recently the primary attack vector utilized by those waging this attack had been crafted requests to the `wp-login.php` script, however a new pattern has recently emerged.

This new attack pattern targets WordPress' XML-RPC facility in the form of requests to `xmlrpc.php`. Actual live attacks observed in the wild by myself and others are directed primarily at the "wp.getUsersBlogs" component, but any component which requires authentication can potentially be used to the same effect.

Attack Payload
--------------
An example of the sort of XML payload posted to ```xmlrpc.php``` in this attack follows:

{% highlight XML %}
<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password1</string></value></param>
  </params>
</methodCall>
{% endhighlight %}

Authentication Failure Response
-------------------------------
When an incorrect set of credentials is supplied in the XML-RPC request a response similar to the following is returned:

{% highlight XML %}
<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
{% endhighlight %}

Successful Method Call Response
-------------------------------
In the event that a valid set of login credentials is supplied, a response similar to the following is returned:

{% highlight XML %}
<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <array><data><value><struct>
        <member>
          <name>isAdmin</name>
          <value><boolean>1</boolean></value>
        </member>
        <member>
          <name>url</name>
          <value><string>http://alzabo.io/</string></value>
        </member>
        <member>
          <name>blogid</name>
          <value><string>1</string></value>
        </member>
        <member>
          <name>blogName</name>
          <value><string>It is a wrong 'em boyo</string></value>
        </member>
        <member>
          <name>xmlrpc</name>
          <value><string>http://alzabo.io/xmlrpc.php</string></value>
        </member>
      </struct></value></data></array>
    </param>
  </params>
</mehodResponse>
{% endhighlight %}

A malicious party will iterate through username and password combinations until a successful response is found. Needless to say, bad times are ahead for sites that have an administrator account's credentials successfully guessed.

Formulating a Defense
---------------------
Basic measures such as using strong passwords and limiting authentication attempts can be utilized by individual site administrators in order to defeat automated attacks such as this.

In my role as a system administrator at a web hosting company I'm responsible for servers that host many thousands of WordPress installs. Even if, in the best of all possible worlds, the majority of customers using WordPress were to employ basic security measures, the distributed nature of the attack would still needlessly consume system resources. In order to more efficiently mitigate this attack a facility which operates at a layer above the WordPress application is required.

Enter ModSecurity
-----------------
ModSecurity is a Web Application Firewall (WAF), which provides a framework for statefully inspecting web traffic and performing actions such as denying access when certain conditions are met. 

A few approaches may be taken here. If no XML-RPC functionality is required, all access to the script may be denied. Specific XML-RPC method calls may also be filtered based on requirements (e.g. only trackbacks & pingbacks are permitted). In cases where a specific site's requirements are not known, a more generalized approach may be taken.

Given that failed XML-RPC authentication attempts generate a predictable response it's possible to use ModSecurity to track method call failures. The following rules initialize a collection capable of persisting across requests and increment a counter when a method call failure occurs:

```
SecAction phase:1,nolog,pass,id:19300,\
    initcol:RESOURCE=%{SERVER_NAME}_%{SCRIPT_FILENAME}
<FilesMatch "xmlrpc.php">
    SecRule RESPONSE_BODY "faultString" "id:19301,nolog,phase:4,\
        t:none,t:urlDecode,setvar:RESOURCE.xmlrpc_bf_counter=+1,\
        deprecatevar:RESOURCE.xmlrpc_bf_counter=1/300"
</FilesMatch>
```


{% gist 20a85ce5187d9dfc159b %}

A [post on Sucri's blog](http://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html) details the particulars of this attack in depth.

