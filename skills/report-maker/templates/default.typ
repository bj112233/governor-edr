#let rtl = __RTL__
#set page(margin: (x: 2cm, y: 2cm))
#set text(size: 11pt)
#set heading(numbering: none)

#if rtl {
  set text(dir: rtl, lang: "he")
}

#align(center)[
  #text(size: 18pt, weight: "bold")[__TITLE__]
  #linebreak()
  #text(size: 10pt, style: "italic")[__DATE__]
]

#v(1em)

__BODY__
