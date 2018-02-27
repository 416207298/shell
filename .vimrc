set nu
set sw=4
set ts=4
set ai
let Tlist_Exit_OnlyWindow=1
let Tlist_Use_Right_Window=1
let Tlist_File_Fold_Auto_Close=1
map <silent> <F9> :TlistToggle<cr>
let Tlist_Auto_Open=1
set showmatch
set smartindent

autocmd InsertLeave * se nocul
autocmd InsertEnter * se cul
syntax enable
syntax on

set tags=/root/trunk/tags
map <c-]> g<c-]>
set autochdir


""set nocompatible              " 去除VI一致性,必须
""filetype off                  " 必须
""" 设置包括vundle和初始化相关的runtime path
""set rtp+=~/.vim/bundle/Vundle.vim
""call vundle#begin()
""Bundle 'altercation/vim-colors-solarized'
""Plugin 'vim-scripts/OmniCppComplete'
""Plugin 'Valloric/YouCompleteMe'
""call vundle#end()
""
""filetype plugin indent on    " 必须 加载vim自带和插件相应的语法和文件类型相关脚本
""" 忽视插件改变缩进,可以使用以下替代:
"""filetype plugin on
"""
""" 简要帮助文档
""" :PluginList       - 列出所有已配置的插件
""" :PluginInstall    - 安装插件,追加 `!` 用以更新或使用 :PluginUpdate
""" :PluginSearch foo - 搜索 foo ; 追加 `!` 清除本地缓存
""" :PluginClean      - 清除未使用插件,需要确认; 追加 `!` 自动批准移除未使用插件
"""
""" 查阅 :h vundle 获取更多细节和wiki以及FAQ
""" 将你自己对非插件片段放在这行之后
""
""let g:ycm_server_keep_logfiles = 1
""let g:ycm_server_log_level = 'debug'

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
Bundle 'sickill/vim-monokai' 
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
set backspace=2
" 光标停留上一次打开位置
au BufReadPost * if line("'\"") > 0|if line("'\"") <= line("$")|exe("norm '\"")|else|exe "norm $"|endif|endif
