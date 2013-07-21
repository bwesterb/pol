" Vim syntax file
" Language:     pol edit
" Maintainer:	Bas Westerbaan <bas@westerbaan.name>
" Filenames:	pol-edit-file
" Last Change:	2013 July 21

" TODO do not highlight faulty lines like
"
"         CONTAINER wee
"
"      and
"
"         only-the-key-no-secret

if exists("b:current_syntax")
  finish
endif

syn case match

syn match poleditKeyString              "^[^\" ]\+" nextgroup=poleditSecretNumber,poleditSecretQString,poleditSecretString
syn match poleditContainerLine          "^CONTAINER \d\+"
syn match poleditComment                "^#.*"

syn region poleditKeyQString            start=/^"/ skip='\\.' end='"' oneline nextgroup=poleditSecretNumber,poleditSecretQString,poleditSecretString
syn region poleditSecretQString         start=/ \+"/ skip='\\.' end='"' oneline contained nextgroup=poleditNote,poleditQNote
syn match poleditSecretString           " \+[^\" ]\+" contained nextgroup=poleditNote,poleditQNote
syn match poleditSecretNumber           " *#\d\+" contained nextgroup=poleditNote,poleditQNote

syn match poleditNote                   " \+[^\"]\+$" contained
syn region poleditQNote                 start=/ \+"/ skip='\\.' end='"' oneline contained contains=poleditEscape
syn match poleditEscape                 "\\[n\\]" contained

hi def link poleditComment              Comment
hi def link poleditContainerLine        Statement
hi def link poleditKeyQString           Identifier
hi def link poleditKeyString            Identifier
hi def link poleditSecretQString        Preproc
hi def link poleditSecretString         Preproc
hi def link poleditSecretNumber         Type
hi def link poleditNote                 String
hi def link poleditQNote                String
hi def link poleditEscape               Preproc

let b:current_syntax = "poledit"
