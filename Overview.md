# Introduction #

REST.NET provides a library and Attribute classes so that serving simple web services via HTTP is as easy as decorating your code.  REST.NET strives to be a very RESTful library, providing rudimentary support for eTags and the missing update issue, as well as being quite simple to use.

## Details ##

This library is based on the ASP.NET WebHandler concept, where a barebones HTTP service is created and put to use.  REST.NET does all of the HTTP bits for you so that you can focus on what's important: your service code.  Inspired by ASP.NET's SOAP service, REST.NET operates under the concepts of code reflection, so that your code just needs the right attributes to work.

## Features ##

  * URI template support (including optional bits)
  * extensible MIME type support
  * support for UTF-8 XML services
  * out-of-the-box handling of HTTP GET, POST, PUT, and DELETE
  * automatic eTag support
  * automatic caching (configurable in Web.config)