/*! `groovy` grammar compiled for Highlight.js 11.3.1 */
var hljsGrammar=(()=>{"use strict";function e(e,a={}){return a.variants=e,a}
return a=>{
const n=a.regex,t="[A-Za-z0-9_$]+",s=e([a.C_LINE_COMMENT_MODE,a.C_BLOCK_COMMENT_MODE,a.COMMENT("/\\*\\*","\\*/",{
relevance:0,contains:[{begin:/\w+@/,relevance:0},{className:"doctag",
begin:"@[A-Za-z]+"}]})]),r={className:"regexp",begin:/~?\/[^\/\n]+\//,
contains:[a.BACKSLASH_ESCAPE]
},i=e([a.BINARY_NUMBER_MODE,a.C_NUMBER_MODE]),l=e([{begin:/"""/,end:/"""/},{
begin:/'''/,end:/'''/},{begin:"\\$/",end:"/\\$",relevance:10
},a.APOS_STRING_MODE,a.QUOTE_STRING_MODE],{className:"string"});return{
name:"Groovy",keywords:{built_in:"this super",literal:"true false null",
keyword:"byte short char int long boolean float double void def as in assert trait abstract static volatile transient public private protected synchronized final class interface enum if else for while switch case break default continue throw throws try catch finally implements extends new import package return instanceof"
},contains:[a.SHEBANG({binary:"groovy",relevance:10}),s,l,r,i,{
className:"class",beginKeywords:"class interface trait enum",end:/\{/,
illegal:":",contains:[{beginKeywords:"extends implements"
},a.UNDERSCORE_TITLE_MODE]},{className:"meta",begin:"@[A-Za-z]+",relevance:0},{
className:"attr",begin:t+"[ \t]*:",relevance:0},{begin:/\?/,end:/:/,relevance:0,
contains:[s,l,r,i,"self"]},{className:"symbol",
begin:"^[ \t]*"+n.lookahead(t+":"),excludeBegin:!0,end:t+":",relevance:0}],
illegal:/#|<\//}}})();export default hljsGrammar;