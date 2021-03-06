set nu
set sw=4
set ts=4
set ai
let Tlist_Exit_OnlyWindow=1
let Tlist_Use_Right_Window=1
let Tlist_File_Fold_Auto_Close=1
" F6开启/关闭左侧树形目录
map <silent> <F5> :NERDTreeToggle<cr>
map <silent> <F6> :NERDTreeToggle<cr>
" F7开启/关闭paste模式
map <silent> <F7> :set paste!<cr>
" F8显示/取消行号
nnoremap <silent> <F8> :set nu!<CR>
" F9显示/关闭Tlist
map <silent> <F9> :TlistToggle<cr>
let Tlist_Auto_Open=1
set showmatch
set smartindent
set ignorecase
set hlsearch
" 逐个字符显示搜索结果
set incsearch
set title

autocmd InsertLeave * se nocul
autocmd InsertEnter * se cul
syntax enable
syntax on

"set tags=/root/gitlearn/trunk/tags
"set tags+=/root/gitlearn/HAC/tags
"set tags+=/root/apue.3e/tags
set tags+=/root/trunk/tags
set tags+=/root/HAC/trunk/tags
"set tags+=/root/codes/LeetCodes/tags
set tags+=/root/codes/network/Tiny-WebServer/tags
set tags+=/root/asv/tags
set tags+=/root/hsm/tags
map <c-]> g<c-]>
set autochdir



set nocompatible              " be iMproved, required
 
" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')
 
" let Vundle manage Vundle, required
Plugin 'VundleVim/Vundle.vim'
 
" The following are examples of different formats supported.
" Keep Plugin commands between vundle#begin/end.
" plugin on GitHub repo
"Plugin 'tpope/vim-fugitive'
" plugin from http://vim-scripts.org/vim/scripts.html
" Plugin 'L9'
" Git plugin not hosted on GitHub
"Plugin 'git://git.wincent.com/command-t.git'
" git repos on your local machine (i.e. when working on your own plugin)
"Plugin 'file:///home/gmarik/path/to/plugin'
" The sparkup vim script is in a subdirectory of this repo called vim.
" Pass the path to set the runtimepath properly.
"Plugin 'rstacruz/sparkup', {'rtp': 'vim/'}
" Install L9 and avoid a Naming conflict if you've already installed a
" different version somewhere else.
" Plugin 'ascenator/L9', {'name': 'newL9'}
Bundle 'kien/ctrlp.vim'
Bundle 'sickill/vim-monokai'
Bundle 'tomasr/molokai'
Plugin 'vim-scripts/OmniCppComplete'
Plugin 'Valloric/YouCompleteMe'
 
" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required
" To ignore plugin indent changes, instead use:
"filetype plugin on
"
" Brief help
" :PluginList       - lists configured plugins
" :PluginInstall    - installs plugins; append `!` to update or just :PluginUpdate
" :PluginSearch foo - searches for foo; append `!` to refresh local cache
" :PluginClean      - confirms removal of unused plugins; append `!` to auto-approve removal
"
" see :h vundle for more details or wiki for FAQ
" Put your non-Plugin stuff after this line
 
colorscheme monokai
 
let g:ycm_global_ycm_extra_conf='~/.vim/bundle/YouCompleteMe/third_party/ycmd/cpp/ycm/.ycm_extra_conf.py'

" 1秒后关闭结构体提示预览窗
let g:ycm_autoclose_preview_window_after_insertion = 1
let g:ycm_autoclose_preview_window_after_completion = 1
" 关闭YCM语法检查
 let g:ycm_enable_diagnostic_signs = 0
 let g:ycm_enable_diagnostic_highlighting = 0

" Go to definition else declaration
nnoremap <leader>jd :YcmCompleter GoToDefinitionElseDeclaration<CR>
" 主动调用补全
let g:ycm_key_invoke_completion = '<C-a>'

set backspace=2
" 光标停留上一次打开位置
au BufReadPost * if line("'\"") > 0|if line("'\"") <= line("$")|exe("norm '\"")|else|exe "norm $"|endif|endif

" 中文乱码解决
if has("multi_byte")
    set fileencodings=utf-8,ucs-bom,cp936,cp1250,big5,euc-jp,euc-kr,latin1,gb-2312
else
    echoerr "Sorry, this version of (g)vim was not compiled with multi_byte"
endif
" set fileencodings=utf-8,ucs-bom,gb18030,gbk,gb2312,cp936
" set termencoding=utf-8
" set encoding=utf-8


 "SET Comment START
 "添加头注释

 autocmd BufNewFile *.php,*.js,*.cpp,*.c exec ":call SetComment()" |normal 10Go
 func SetComment()
 if expand("%:e") == 'php'
     call setline(1, "<?php")
 elseif expand("%:e") == 'js'
     call setline(1, '//JavaScript file')
 elseif expand("%:e") == 'cpp'
     call setline(1, '//C++ file')
 elseif expand("%:e") == 'c'
     call setline(1, '//C file')
 elseif expand("%:e") == 'py'
     call setline(1, '//Python file')
 endif
 call append(1, '/***********************************************')
 call append(2, '#')
 call append(3, '#      Filename: '.expand("%"))
 call append(4, '#')
 call append(5, '#        Author: luhg - luhg@keyou.cn')
 call append(6, '#   Description: ---')
 call append(7, '#        Create: '.strftime("%Y-%m-%d %H:%M:%S"))
 call append(8, '#**********************************************/')
 if expand("%:e") == 'cpp'
	 call append(9, '#include<iostream>')
	 call append(10, 'using namespace std;')
 elseif expand("%:e") == 'c'
	 call append(9, '#include<stdio.h>')
 elseif expand("%:e") == 'py'
	 call append(9, '# -*- coding:utf-8 -*')
 endif
endfunc
" map <F2> :call SetComment()<CR>:10<CR>o

"SET Comment END

 " 添加函数注释开始
 "autocmd BufNewFile *.php,*.js,*.cpp exec ":call SetComment2()" |normal line('.')Go
 func SetComment2()
 call append(line('.'), '/***********************************************')
 call append(line('.')+1, '#      函数名称:')
 call append(line('.')+2, '#')
 call append(line('.')+3, '#   Description:')
 call append(line('.')+4, '#     parameter:')
 call append(line('.')+5, '#   returnValue:')
 call append(line('.')+6, '#   	 Author: luhg')
 call append(line('.')+7, '#        Create: '.strftime("%Y-%m-%d %H:%M:%S"))
 call append(line('.')+8, '#**********************************************/')
endfunc
map <F1> :call SetComment2()<CR>

" 函数注释END
