---
layout: post
title:  Defending WordPress from XML-RPC brute force attacks
date:   2014-09-15 00:08:00
categories: ModSecurity
---
Over the course of the last year a tremendous remote brute force (password guessing) attack campaign has been waged against web sites built with the popular blogging platform WordPress. Until recently the primary attack vector utilized by those waging this attack had been crafted requests to the `wp-login.php` script, however a new pattern has recently emerged.

This new attack pattern targets WordPress' XML-RPC facility in the form of requests to `xmlrpc.php`. Actual live attacks observed in the wild by myself and others are directed primarily at the "wp.getUsersBlogs" component, but any component which requires authentication can potentially be used to the same effect.

An example of the sort of payload data used in this new attack pattern follows:

{% highlight XML %}
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password1</string></value></param>
  </params>
</methodCall>
{% endhighlight %}

Enter ModSecurity
=================
ModSecurity is a Web Application Firewall (WAF) which can be utilized to analyze traffic to and from a web server and perform a variety of actions.

A [post on Sucri's blog](http://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html) details the particulars of this attack in depth.

*[WAF]: Web Application Firewall
