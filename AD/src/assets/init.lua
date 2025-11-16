-- Minimal nvim config:


vim.opt.number = true
vim.opt.relativenumber = true
vim.g.mapleader = " "
vim.opt.mouse = 'a'
vim.opt.showmode = false
vim.opt.listchars = { tab = '» ', trail = '·', nbsp = '␣' }
-- Lines:
vim.opt.cursorline = true


-- Bootstrap lazy.nvim
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not (vim.uv or vim.loop).fs_stat(lazypath) then
  local lazyrepo = "https://github.com/folke/lazy.nvim.git"
  local out = vim.fn.system({ "git", "clone", "--filter=blob:none", "--branch=stable", lazyrepo, lazypath })
  if vim.v.shell_error ~= 0 then
    vim.api.nvim_echo({
      { "Failed to clone lazy.nvim:\n", "ErrorMsg" },
      { out, "WarningMsg" },
      { "\nPress any key to exit..." },
    }, true, {})
    vim.fn.getchar()
    os.exit(1)
  end
end
vim.opt.rtp:prepend(lazypath)

-- Setup lazy.nvim and install plugins:
require("lazy").setup({
  spec = {
{ "folke/todo-comments.nvim", opts = {} },
{ 'nvim-neo-tree/neo-tree.nvim', version = '*', dependencies = { 'nvim-lua/plenary.nvim', 'nvim-tree/nvim-web-devicons', 'MunifTanjim/nui.nvim', },
  cmd = 'Neotree',
  keys = {
    { '\\', ':Neotree reveal<CR>', desc = 'NeoTree reveal', silent = true },
  },
  opts = {
    filesystem = {
      filtered_items = { visible = true, hide_dotfiles = false, hide_gitignored = true, hide_by_name = {'.git',},},
      window = { position = 'right', width = 28, mappings = { ['\\'] = 'close_window', },},
      },
    },
  },
-- Fuzzy Finder and better file navigator
{ 'nvim-telescope/telescope.nvim', event = 'VimEnter', branch = '0.1.x', }, {'stevearc/oil.nvim'}, 
  },
})
