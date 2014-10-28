---
layout: post
title:  Defending WordPress from XML-RPC brute force attacks
date:   2014-09-15 00:08:00
categories: modsecurity
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

Given that failed XML-RPC authentication attempts generate a predictable response it's possible to use ModSecurity to track method call failures. The following rules initialize a collection capable of persisting across requests and increment a counter when a method call failure occurs.

Note that these rules set up a collection which will track XML-RPC method call failures on a _per remote IP basis_. As such, these rules as written will only be effective against attacks that are not highly distributed, i.e. a series of brute force attempts coming from a single remote host.

A more aggressive version of these rules which is effective against distributed attacks is described a bit further on.

```
SecAction "phase:1,nolog,pass,id:19300,\
    initcol:ip=%{REMOTE_ADDR}"

SecRule RESPONSE_BODY "faultString" "id:19301,nolog,phase:4,\
    t:none,t:urlDecode,setvar:ip.xmlrpc_bf_counter=+1,\
    deprecatevar:ip.xmlrpc_bf_counter=1/300,pass"
```


The following rules examine the value stored in ```xmlrpc_bf_counter``` and deny access to XML-RPC method calls beginning with the string "wp." after 5 method call failures have been recorded.

```
SecRule STREAM_INPUT_BODY "<methodCall>wp\." "id:19302,log,chain,\
    deny,status:406,phase:4,t:none,t:urlDecode,\
    msg:'Temporary block due to multiple XML-RPC method call failures'"

SecRule ip:xmlrpc_bf_counter "@gt 4" "t:none,t:urlDecode,\
    t:removeWhitespace"
```

Complete Rule Set
-----------------
In order for the rules above to function as intended a number of ModSecurity configuration directives need to be set. The combined rule set along with all necessary configuration directives are included below in an Apache 2.x-style format.

{% gist 7ab74c634b43352bdbdb %}

Stopping Distributed Attacks
----------------------------

The rule set above becomes ineffective when faced with highly-distributed attacks. A more aggressive version which disables access to XML-RPC methods under the "wp" namespace after 5 failures from _any combination of IPs_ may be found [in this gist](https://gist.github.com/arg0sy/20a85ce5187d9dfc159b).

This more aggressive rule set has a _far higher chance of blocking legitimate XML-RPC method calls_.

Notes, Caveats & Further Reading
--------------------------------

Both rule set variants have potential to interfere with popular plugins such as Jetpack that rely heavily on XML-RPC. I'm entirely open to contributions designed to limit such interference via whitelisting or other means.

For more details on the particulars of this attack trend, refer to [this post on Sucuri's blog](http://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html).

A good place to begin learning more about ModSecurity is the [project wiki on github](https://github.com/SpiderLabs/ModSecurity/wiki).

