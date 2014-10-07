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
Individual site administrators can take some basic measures to help ensure they don't fall victim to this sort of password-guessing attack.

1. Choose a *good* password
1. Limit authentication attempts.
1. Disable unneeded features

In my role as a system administrator at a web hosting company it's simply not realistic to expect all customers running WordPress to make these sorts of site-level changes. A higher-level form of defense is required.

Enter ModSecurity
-----------------
ModSecurity is a Web Application Firewall (WAF), which provides a framework for statefully inspecting web traffic and performing actions such as denying access when certain conditions are met. 

A few approaches may be taken here. If no XML-RPC functionality is required, all access to the script may be denied. Specific XML-RPC method calls may also be filtered based on requirements (e.g. only trackbacks & pingbacks are permitted). In cases where a specific site's requirements are not known, a more generalized approach may be taken.

The code below uses Apache config ```<FilesMatch ...>...</FilesMatch>``` directives in order to limit the scope to which the rules are applied. This facet of the code sample may need to be adjusted for other web servers.

{% gist 20a85ce5187d9dfc159b %}

A [post on Sucri's blog](http://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html) details the particulars of this attack in depth.

