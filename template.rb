

initializer 'generators.rb', <<-RUBY
Rails.application.config.generators do |g|
end
RUBY


def say_custom(tag, text); say "\033[1m\033[36m" + tag.to_s.rjust(10) + "\033[0m" + "  #{text}" end
def say_recipe(name); say "\033[1m\033[36m" + "recipe".rjust(10) + "\033[0m" + "  Running #{name} recipe..." end
def say_wizard(text); say_custom(@current_recipe || 'wizard', text) end
@after_everything_blocks = []
def after_everything(&block); @after_everything_blocks << [@current_recipe, block]; end


say_recipe 'Git'

after_everything do
  git :init
  git :add => '.'
  git :commit => '-m "Initial import."'
end


say_recipe "Unicorn"
gem 'unicorn'
file 'config/unicorn.rb', <<-CODE
env = ENV["RAILS_ENV"] || "development"
worker_processes 4

shared_path = "/var/www/#{app_name}/shared"
shared_path = "." if env == "development"

stderr_path "#\{shared_path}/log/unicorn.stderr.log"
stdout_path "#\{shared_path}/log/unicorn.stdout.log"

unless env == "development"
  pid "#\{shared_path}/pids/unicorn.pid"
  listen "#\{shared_path}/sockets/unicorn.socket", backlog: 64
end


preload_app true
listen 3000
timeout 30


before_fork do |server, worker|
  if defined?(ActiveRecord::Base)
    ActiveRecord::Base.connection.disconnect!
  end

  old_pid = "/tmp/unicorn.pid.oldbin"
  if File.exists?(old_pid) && server.pid != old_pid
    begin
      Process.kill("QUIT", File.read(old_pid).to_i)
    rescue Errno::ENOENT, Errno::ESRCH
      # someone else did our job for us
    end
  end
end

after_fork do |server, worker|
  if defined?(ActiveRecord::Base)
    ActiveRecord::Base.establish_connection
  end
  #GC.disable if Rails.env.production? || Rails.env.staging?
end
CODE




say_recipe 'Server'
gsub_file "Gemfile", /sqlite3/, "pg"
file 'config/database.yml', <<-CODE
development:
  adapter: postgresql
  encoding: unicode
  pool: 15
  database: #{app_name}_development

staging:
  adapter: postgresql
  encoding: unicode
  pool: 20
  database: #{app_name}_staging

production:
  adapter: postgresql
  encoding: utf8
  pool: 60
  host: db-1.#{app_name}.io
  username: deploy
  password: deploy
  database: #{app_name}

test:
  adapter: postgresql
  encoding: utf8
  pool: 5
  database: #{app_name}_test
CODE
file 'config/environments/staging.rb', File.read('config/environments/production.rb')
gsub_file 'config/environments/staging.rb', /log_level = :info/, "log_level = :debug"

gem 'god'
gem 'dalli'
gem 'state_machine'
gem 'validate_email'
gem 'kaminari'
gem 'rails-i18n'
gem 'airbrake'
gem 'whenever', :require => false
gem 'therubyracer', :require => 'v8'
initializer 'sidekiq.rb', <<-CODE
require 'bigdecimal/util'

class NilClass
  def to_d
    BigDecimal("0")
  end
end
CODE




say_recipe 'HAML'
gem 'haml', '>= 3.0.0'
gem 'haml-rails'



say_recipe 'Sidekiq'
gem 'sinatra', '>= 1.3.0', :require => nil
gem 'sidekiq', '2.17.7'
gem 'sidekiq-failures'

route "require 'sidekiq/web'"
route " mount Sidekiq::Web => '/sidekiq'"
file 'config/sidekiq.yml', <<-CODE
---
:verbose: false
:pidfile: ./tmp/pids/sidekiq.pid
staging:
  :concurrency: 2
production:
  :concurrency: 50
:queues:
  - [default, 5]
CODE
initializer 'sidekiq.rb', <<-CODE
require 'sidekiq/web'

host ={
    development:  '127.0.0.1:6379',
    staging:      '127.0.0.1:6379',
    test:         '127.0.0.1:6379',
    production:   'wrk-1.host.ee:6379' }[Rails.env.to_sym]


Sidekiq.configure_server do |config|
  config.redis = { :url => "redis://#\{host}/12", :namespace => 'sidekiq:shoperb' }
end

Sidekiq.configure_client do |config|
  config.redis  = { :url => "redis://#\{host}/12", :namespace => 'sidekiq:shoperb'}
end


Sidekiq::Web.use Rack::Auth::Basic, "Sidekiq" do |username, password|
  username == "sidekiq" && password == "#{SecureRandom.hex(7)}"
end if Rails.env.production?
CODE


say_recipe 'Bettter Errors'
gem_group :development do
  gem 'better_errors'
  gem 'binding_of_caller', platform: :mri
end




say_recipe 'Sequel'
gem 'sequel-rails'
application "require 'sequel-rails/railtie'"

# >-----------------------------[ Run Bundler ]-------------------------------<

say_wizard "Running Bundler install. This will take a while."
run 'bundle install'





# >----------------------------[ Initial Setup ]------------------------------<
=begin
module Gemfile
  class GemInfo
    def initialize(name) @name=name; @group=[]; @opts={}; end
    attr_accessor :name, :version
    attr_reader :group, :opts

    def opts=(new_opts={})
      new_group = new_opts.delete(:group)
      if (new_group && self.group != new_group)
        @group = ([self.group].flatten + [new_group].flatten).compact.uniq.sort
      end
      @opts = (self.opts || {}).merge(new_opts)
    end

    def group_key() @group end

    def gem_args_string
      args = ["'#{@name}'"]
      args << "'#{@version}'" if @version
      @opts.each do |name,value|
        args << ":#{name}=>#{value.inspect}"
      end
      args.join(', ')
    end
  end

  @geminfo = {}

  class << self
    # add(name, version, opts={})
    def add(name, *args)
      name = name.to_s
      version = args.first && !args.first.is_a?(Hash) ? args.shift : nil
      opts = args.first && args.first.is_a?(Hash) ? args.shift : {}
      @geminfo[name] = (@geminfo[name] || GemInfo.new(name)).tap do |info|
        info.version = version if version
        info.opts = opts
      end
    end

    def write
      File.open('Gemfile', 'a') do |file|
        file.puts
        grouped_gem_names.sort.each do |group, gem_names|
          indent = ""
          unless group.empty?
            file.puts "group :#{group.join(', :')} do" unless group.empty?
            indent="  "
          end
          gem_names.sort.each do |gem_name|
            file.puts "#{indent}gem #{@geminfo[gem_name].gem_args_string}"
          end
          file.puts "end" unless group.empty?
          file.puts
        end
      end
    end

    private
    #returns {group=>[...gem names...]}, ie {[:development, :test]=>['rspec-rails', 'mocha'], :assets=>[], ...}
    def grouped_gem_names
      {}.tap do |_groups|
        @geminfo.each do |gem_name, geminfo|
          (_groups[geminfo.group_key] ||= []).push(gem_name)
        end
      end
    end
  end
end
def add_gem(*all) Gemfile.add(*all); end

@recipes = ["core", "git", "railsapps", "setup", "readme", "gems", "testing", "tests4", "email", "models", "controllers", "views", "routes", "frontend", "init", "apps4", "prelaunch", "saas", "extras", "deployment"]
@prefs = {}
@gems = []
@diagnostics_recipes = [["example"], ["setup"], ["railsapps"], ["gems", "setup"], ["gems", "readme", "setup"], ["extras", "gems", "readme", "setup"], ["example", "git"], ["git", "setup"], ["git", "railsapps"], ["gems", "git", "setup"], ["gems", "git", "readme", "setup"], ["extras", "gems", "git", "readme", "setup"], ["controllers", "email", "extras", "frontend", "gems", "git", "init", "models", "railsapps", "readme", "routes", "setup", "testing", "views"], ["controllers", "core", "email", "extras", "frontend", "gems", "git", "init", "models", "railsapps", "readme", "routes", "setup", "testing", "views"], ["controllers", "core", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "setup", "testing", "views"], ["controllers", "core", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "views"], ["controllers", "email", "example", "extras", "frontend", "gems", "git", "init", "models", "railsapps", "readme", "routes", "setup", "testing", "views"], ["controllers", "email", "example", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "setup", "testing", "views"], ["controllers", "email", "example", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "views"], ["apps4", "controllers", "core", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "views"], ["apps4", "controllers", "core", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "tests4", "views"], ["apps4", "controllers", "core", "deployment", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "views"], ["apps4", "controllers", "core", "deployment", "email", "extras", "frontend", "gems", "git", "init", "models", "prelaunch", "railsapps", "readme", "routes", "saas", "setup", "testing", "tests4", "views"]]

diagnostics = {}

# >-------------------------- templates/helpers.erb --------------------------start<
def recipes; @recipes end
def recipe?(name); @recipes.include?(name) end
def prefs; @prefs end
def prefer(key, value); @prefs[key].eql? value end
def gems; @gems end
def diagnostics_recipes; @diagnostics_recipes end

def say_custom(tag, text); say "\033[1m\033[36m" + tag.to_s.rjust(10) + "\033[0m" + "  #{text}" end
def say_recipe(name); say "\033[1m\033[36m" + "recipe".rjust(10) + "\033[0m" + "  Running #{name} recipe..." end
def say_wizard(text); say_custom(@current_recipe || 'composer', text) end


def ask_wizard(question)
  ask "\033[1m\033[36m" + (@current_recipe || "prompt").rjust(10) + "\033[1m\033[36m" + "  #{question}\033[0m"
end

def yes_wizard?(question)
  answer = ask_wizard(question + " \033[33m(y/n)\033[0m")
  case answer.downcase
    when "yes", "y"
      true
    when "no", "n"
      false
    else
      yes_wizard?(question)
  end
end





def copy_from(source, destination)
  begin
    remove_file destination
    get source, destination
  rescue OpenURI::HTTPError
    say_wizard "Unable to obtain #{source}"
  end
end

def copy_from_repo(filename, opts = {})
  repo = 'https://raw.github.com/RailsApps/rails-composer/master/files/'
  repo = opts[:repo] unless opts[:repo].nil?
  if (!opts[:prefs].nil?) && (!prefs.has_value? opts[:prefs])
    return
  end
  source_filename = filename
  destination_filename = filename
  unless opts[:prefs].nil?
    if filename.include? opts[:prefs]
      destination_filename = filename.gsub(/\-#{opts[:prefs]}/, '')
    end
  end
  if (prefer :templates, 'haml') && (filename.include? 'views')
    remove_file destination_filename
    destination_filename = destination_filename.gsub(/.erb/, '.haml')
  end
  begin
    remove_file destination_filename
    if (prefer :templates, 'haml') && (filename.include? 'views')
      create_file destination_filename, html_to_haml(repo + source_filename)
    elsif (prefer :templates, 'slim') && (filename.include? 'views')
      create_file destination_filename, html_to_slim(repo + source_filename)
    else
      get repo + source_filename, destination_filename
    end
  rescue OpenURI::HTTPError
    say_wizard "Unable to obtain #{source_filename} from the repo #{repo}"
  end
end

def html_to_haml(source)
  begin
    html = open(source) {|input| input.binmode.read }
    Haml::HTML.new(html, :erb => true, :xhtml => true).render
  rescue RubyParser::SyntaxError
    say_wizard "Ignoring RubyParser::SyntaxError"
    # special case to accommodate https://github.com/RailsApps/rails-composer/issues/55
    html = open(source) {|input| input.binmode.read }
    say_wizard "applying patch" if html.include? 'card_month'
    say_wizard "applying patch" if html.include? 'card_year'
    html = html.gsub(/, {add_month_numbers: true}, {name: nil, id: "card_month"}/, '')
    html = html.gsub(/, {start_year: Date\.today\.year, end_year: Date\.today\.year\+10}, {name: nil, id: "card_year"}/, '')
    result = Haml::HTML.new(html, :erb => true, :xhtml => true).render
    result = result.gsub(/select_month nil/, "select_month nil, {add_month_numbers: true}, {name: nil, id: \"card_month\"}")
    result = result.gsub(/select_year nil/, "select_year nil, {start_year: Date.today.year, end_year: Date.today.year+10}, {name: nil, id: \"card_year\"}")
  end
end


# full credit to @mislav in this StackOverflow answer for the #which() method:
# - http://stackoverflow.com/a/5471032
def which(cmd)
  exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
  ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
    exts.each do |ext|
    exe = "#{path}#{File::SEPARATOR}#{cmd}#{ext}"
      return exe if File.executable? exe
    end
  end
  return nil
end


# >---------------------------[ Autoload Modules/Classes ]-----------------------------<

inject_into_file 'config/application.rb', :after => 'config.autoload_paths += %W(#{config.root}/extras)' do <<-'RUBY'

    config.autoload_paths += %W(#{config.root}/lib)
RUBY
end

# >---------------------------------[ Recipes ]----------------------------------<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ core ]----------------------------------<
@current_recipe = "core"
@before_configs["core"].call if @before_configs["core"]
say_recipe 'core'
@configs[@current_recipe] = config
# >----------------------------- recipes/core.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/core.rb

## Git
say_wizard "selected all core recipes"
# >----------------------------- recipes/core.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >----------------------------------[ git ]----------------------------------<
@current_recipe = "git"
@before_configs["git"].call if @before_configs["git"]
say_recipe 'git'
@configs[@current_recipe] = config
# >----------------------------- recipes/git.rb ------------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/git.rb

## Git
say_wizard "initialize git"
prefs[:git] = true unless prefs.has_key? :git
if prefer :git, true
  copy_from 'https://raw.github.com/RailsApps/rails-composer/master/files/gitignore.txt', '.gitignore'
  git :init
  git :add => '-A'
  git :commit => '-qm "rails_apps_composer: initial commit"'
else
  after_everything do
    say_wizard "removing .gitignore and .gitkeep files"
    git_files = Dir[File.join('**','.gitkeep')] + Dir[File.join('**','.gitignore')]
    File.unlink git_files
  end
end
# >----------------------------- recipes/git.rb ------------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >-------------------------------[ railsapps ]-------------------------------<
@current_recipe = "railsapps"
@before_configs["railsapps"].call if @before_configs["railsapps"]
say_recipe 'railsapps'
@configs[@current_recipe] = config
# >-------------------------- recipes/railsapps.rb ---------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/railsapps.rb

raise if (defined? defaults) || (defined? preferences) # Shouldn't happen.
if options[:verbose]
  print "\nrecipes: ";p recipes
  print "\ngems: "   ;p gems
  print "\nprefs: "  ;p prefs
  print "\nconfig: " ;p config
end

case Rails::VERSION::MAJOR.to_s
when "3"
  prefs[:railsapps] = multiple_choice "Install an example application for Rails 3.2?",
    [["I want to build my own application", "none"],
    ["membership/subscription/saas", "saas"],
    ["rails-prelaunch-signup", "rails-prelaunch-signup"],
    ["rails3-bootstrap-devise-cancan", "rails3-bootstrap-devise-cancan"],
    ["rails3-devise-rspec-cucumber", "rails3-devise-rspec-cucumber"],
    ["rails3-mongoid-devise", "rails3-mongoid-devise"],
    ["rails3-mongoid-omniauth", "rails3-mongoid-omniauth"],
    ["rails3-subdomains", "rails3-subdomains"]] unless prefs.has_key? :railsapps
when "4"
  prefs[:apps4] = multiple_choice "Build a starter application?",
    [["Build a RailsApps example application", "railsapps"],
    ["Build a contributed application", "contributed_app"],
    ["I want to build my own application", "none"]] unless prefs.has_key? :apps4
  case prefs[:apps4]
    when 'railsapps'
      if rails_4_1?
        prefs[:apps4] = prefs[:rails_4_1_starter_app] || (multiple_choice "Starter apps for Rails 4.1. More to come.",
        [["learn-rails", "learn-rails"],
        ["rails-bootstrap", "rails-bootstrap"],
        ["rails-foundation", "rails-foundation"],
        ["rails-omniauth", "rails-omniauth"],
        ["rails-devise", "rails-devise"],
        ["rails-devise-pundit", "rails-devise-pundit"]])
      else
        say_wizard "Please upgrade to Rails 4.1 to get the starter apps."
      end
    when 'contributed_app'
      prefs[:apps4] = multiple_choice "No contributed applications are available.",
        [["continue", "none"]]
  end
end

case prefs[:apps4]
  when 'simple-test'
    prefs[:dev_webserver] = 'webrick'
    prefs[:prod_webserver] = 'same'
    prefs[:templates] = 'erb'
    prefs[:git] = false
    prefs[:github] = false
    prefs[:database] = 'sqlite'
    prefs[:unit_test] = false
    prefs[:integration] = false
    prefs[:fixtures] = false
    prefs[:frontend] = false
    prefs[:email] = false
    prefs[:authentication] = false
    prefs[:devise_modules] = false
    prefs[:authorization] = false
    prefs[:starter_app] = false
    prefs[:form_builder] = false
    prefs[:quiet_assets] = false
    prefs[:local_env_file] = 'none'
    prefs[:better_errors] = false
    prefs[:pry] = false
    prefs[:deployment] = 'none'
    prefs[:ban_spiders] = false
    prefs[:continuous_testing] = false
  when 'learn-rails'
    prefs[:dev_webserver] = 'webrick'
    prefs[:prod_webserver] = 'same'
    prefs[:templates] = 'erb'
    prefs[:git] = true
    prefs[:database] = 'default'
    prefs[:frontend] = 'foundation5'
    prefs[:email] = 'gmail'
    prefs[:authentication] = false
    prefs[:devise_modules] = false
    prefs[:authorization] = false
    prefs[:starter_app] = false
    prefs[:form_builder] = 'simple_form'
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = 'none'
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
    prefs[:ban_spiders] = false
    prefs[:github] = false
  when 'rails-bootstrap'
    prefs[:git] = true
    prefs[:database] = 'default'
    prefs[:frontend] = 'bootstrap3'
    prefs[:email] = 'none'
    prefs[:authentication] = false
    prefs[:devise_modules] = false
    prefs[:authorization] = false
    prefs[:starter_app] = false
    prefs[:form_builder] = false
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = false
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
  when 'rails-foundation'
    prefs[:git] = true
    prefs[:database] = 'default'
    prefs[:frontend] = 'foundation5'
    prefs[:email] = 'none'
    prefs[:authentication] = false
    prefs[:devise_modules] = false
    prefs[:authorization] = false
    prefs[:starter_app] = false
    prefs[:form_builder] = false
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = false
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
  when 'rails-devise'
    prefs[:git] = true
    prefs[:authentication] = 'devise'
    prefs[:authorization] = false
    prefs[:starter_app] = false
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = false
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
  when 'rails-devise-pundit'
    prefs[:git] = true
    prefs[:authentication] = 'devise'
    prefs[:authorization] = 'pundit'
    prefs[:starter_app] = 'admin_app'
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = false
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
  when 'rails-omniauth'
    prefs[:git] = true
    prefs[:email] = 'none'
    prefs[:authentication] = 'omniauth'
    prefs[:authorization] = 'none'
    prefs[:starter_app] = false
    prefs[:quiet_assets] = true
    prefs[:local_env_file] = false
    prefs[:better_errors] = true
    prefs[:pry] = false
    prefs[:deployment] = 'none'
end


# >-------------------------- recipes/railsapps.rb ---------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ setup ]---------------------------------<
@current_recipe = "setup"
@before_configs["setup"].call if @before_configs["setup"]
say_recipe 'setup'
@configs[@current_recipe] = config
# >---------------------------- recipes/setup.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/setup.rb

## Ruby on Rails
HOST_OS = RbConfig::CONFIG['host_os']
say_wizard "Your operating system is #{HOST_OS}."
say_wizard "You are using Ruby version #{RUBY_VERSION}."
say_wizard "You are using Rails version #{Rails::VERSION::STRING}."

## Is sqlite3 in the Gemfile?
gemfile = File.read(destination_root() + '/Gemfile')
sqlite_detected = gemfile.include? 'sqlite3'

## Web Server
prefs[:dev_webserver] = multiple_choice "Web server for development?", [["WEBrick (default)", "webrick"],
  ["Thin", "thin"], ["Unicorn", "unicorn"], ["Puma", "puma"], ["Phusion Passenger (Apache/Nginx)", "passenger"],
  ["Phusion Passenger (Standalone)", "passenger_standalone"]] unless prefs.has_key? :dev_webserver
prefs[:prod_webserver] = multiple_choice "Web server for production?", [["Same as development", "same"],
  ["Thin", "thin"], ["Unicorn", "unicorn"], ["Puma", "puma"], ["Phusion Passenger (Apache/Nginx)", "passenger"],
  ["Phusion Passenger (Standalone)", "passenger_standalone"]] unless prefs.has_key? :prod_webserver
if prefs[:prod_webserver] == 'same'
  case prefs[:dev_webserver]
    when 'thin'
      prefs[:prod_webserver] = 'thin'
    when 'unicorn'
      prefs[:prod_webserver] = 'unicorn'
    when 'puma'
      prefs[:prod_webserver] = 'puma'
    when 'passenger'
      prefs[:prod_webserver] = 'passenger'
    when 'passenger_standalone'
      prefs[:prod_webserver] = 'passenger_standalone'
  end
end

## Database Adapter
if rails_4_1?
  prefs[:database] = multiple_choice "Database used in development?", [["SQLite", "sqlite"], ["PostgreSQL", "postgresql"],
    ["MySQL", "mysql"]] unless prefs.has_key? :database
else
  prefs[:database] = multiple_choice "Database used in development?", [["SQLite", "sqlite"], ["PostgreSQL", "postgresql"],
    ["MySQL", "mysql"], ["MongoDB", "mongodb"]] unless prefs.has_key? :database
end
case prefs[:database]
  when 'mongodb'
    unless sqlite_detected
      prefs[:orm] = multiple_choice "How will you connect to MongoDB?", [["Mongoid","mongoid"]] unless prefs.has_key? :orm
    else
      say_wizard "WARNING! SQLite gem detected in the Gemfile"
      say_wizard "If you wish to use MongoDB you must skip Active Record."
      say_wizard "If using rails_apps_composer, choose 'skip Active Record'."
      say_wizard "If using Rails Composer or an application template, use the '-O' flag as in 'rails new foo -O'."
      prefs[:fail] = multiple_choice "Abort or continue?", [["abort", "abort"], ["continue", "continue"]]
      if prefer :fail, 'abort'
        raise StandardError.new "SQLite detected in the Gemfile. Use '-O' or '--skip-activerecord' as in 'rails new foo -O' if you don't want ActiveRecord and SQLite"
      end
    end
end

## Template Engine
prefs[:templates] = multiple_choice "Template engine?", [["ERB", "erb"], ["Haml", "haml"], ["Slim", "slim"]] unless prefs.has_key? :templates

## Testing Framework
if rails_4_1?
  if recipes.include? 'tests4'
    prefs[:tests] = multiple_choice "Test framework?", [["None", "none"],
      ["RSpec with Capybara", "rspec"]] unless prefs.has_key? :tests
    case prefs[:tests]
      when 'rspec'
        say_wizard "Adding DatabaseCleaner, FactoryGirl, Faker, Launchy, Selenium"
        prefs[:continuous_testing] = multiple_choice "Continuous testing?", [["None", "none"], ["Guard", "guard"]] unless prefs.has_key? :continuous_testing
      end
  end
else
  if recipes.include? 'testing'
    prefs[:unit_test] = multiple_choice "Unit testing?", [["Test::Unit", "test_unit"], ["RSpec", "rspec"], ["MiniTest", "minitest"]] unless prefs.has_key? :unit_test
    prefs[:integration] = multiple_choice "Integration testing?", [["None", "none"], ["RSpec with Capybara", "rspec-capybara"],
      ["Cucumber with Capybara", "cucumber"], ["Turnip with Capybara", "turnip"], ["MiniTest with Capybara", "minitest-capybara"]] unless prefs.has_key? :integration
    prefs[:continuous_testing] = multiple_choice "Continuous testing?", [["None", "none"], ["Guard", "guard"]] unless prefs.has_key? :continuous_testing
    prefs[:fixtures] = multiple_choice "Fixture replacement?", [["None","none"], ["Factory Girl","factory_girl"], ["Machinist","machinist"], ["Fabrication","fabrication"]] unless prefs.has_key? :fixtures
  end
end

## Front-end Framework
if recipes.include? 'frontend'
  prefs[:frontend] = multiple_choice "Front-end framework?", [["None", "none"],
    ["Bootstrap 3.0", "bootstrap3"], ["Bootstrap 2.3", "bootstrap2"],
    ["Zurb Foundation 5.0", "foundation5"], ["Zurb Foundation 4.0", "foundation4"],
    ["Simple CSS", "simple"]] unless prefs.has_key? :frontend
end

## Email
if recipes.include? 'email'
  unless prefs.has_key? :email
    say_wizard "The Devise 'forgot password' feature requires email." if prefer :authentication, 'devise'
    prefs[:email] = multiple_choice "Add support for sending email?", [["None", "none"], ["Gmail","gmail"], ["SMTP","smtp"],
      ["SendGrid","sendgrid"], ["Mandrill","mandrill"]]
  end
else
  prefs[:email] = 'none'
end

## Authentication and Authorization
if recipes.include? 'models'
  prefs[:authentication] = multiple_choice "Authentication?", [["None", "none"], ["Devise", "devise"], ["OmniAuth", "omniauth"]] unless prefs.has_key? :authentication
  case prefs[:authentication]
    when 'devise'
      if prefer :orm, 'mongoid'
        prefs[:devise_modules] = multiple_choice "Devise modules?", [["Devise with default modules","default"]] unless prefs.has_key? :devise_modules
      else
        prefs[:devise_modules] = multiple_choice "Devise modules?", [["Devise with default modules","default"],
        ["Devise with Confirmable module","confirmable"]] unless prefs.has_key? :devise_modules
      end
    when 'omniauth'
      prefs[:omniauth_provider] = multiple_choice "OmniAuth provider?", [["Facebook", "facebook"], ["Twitter", "twitter"], ["GitHub", "github"],
        ["LinkedIn", "linkedin"], ["Google-Oauth-2", "google_oauth2"], ["Tumblr", "tumblr"]] unless prefs.has_key? :omniauth_provider
  end
  unless prefs.has_key? :authorization
    prefs[:authorization] = multiple_choice "Authorization?", [["None", "none"], ["Pundit", "pundit"]]
  end
end

## Form Builder
prefs[:form_builder] = multiple_choice "Use a form builder gem?", [["None", "none"], ["SimpleForm", "simple_form"]] unless prefs.has_key? :form_builder

## MVC
if (recipes.include? 'models') && (recipes.include? 'controllers') && (recipes.include? 'views') && (recipes.include? 'routes')
  if (prefer :authorization, 'cancan') or (prefer :authorization, 'pundit')
    prefs[:starter_app] = multiple_choice "Install a starter app?", [["None", "none"], ["Home Page", "home_app"],
      ["Home Page, User Accounts", "users_app"], ["Home Page, User Accounts, Admin Dashboard", "admin_app"]] unless prefs.has_key? :starter_app
  elsif prefer :authentication, 'devise'
    if prefer :orm, 'mongoid'
      prefs[:starter_app] = multiple_choice "Install a starter app?", [["None", "none"], ["Home Page", "home_app"],
        ["Home Page, User Accounts", "users_app"], ["Home Page, User Accounts, Subdomains", "subdomains_app"]] unless prefs.has_key? :starter_app
    else
      prefs[:starter_app] = multiple_choice "Install a starter app?", [["None", "none"], ["Home Page", "home_app"],
        ["Home Page, User Accounts", "users_app"]] unless prefs.has_key? :starter_app
    end
  elsif prefer :authentication, 'omniauth'
    prefs[:starter_app] = multiple_choice "Install a starter app?", [["None", "none"], ["Home Page", "home_app"],
      ["Home Page, User Accounts", "users_app"]] unless prefs.has_key? :starter_app
  else
    prefs[:starter_app] = multiple_choice "Install a starter app?", [["None", "none"], ["Home Page", "home_app"]] unless prefs.has_key? :starter_app
  end
end

# save diagnostics before anything can fail
create_file "README", "RECIPES\n#{recipes.sort.inspect}\n"
append_file "README", "PREFERENCES\n#{prefs.inspect}"
# >---------------------------- recipes/setup.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ readme ]---------------------------------<
@current_recipe = "readme"
@before_configs["readme"].call if @before_configs["readme"]
say_recipe 'readme'
@configs[@current_recipe] = config
# >---------------------------- recipes/readme.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/readme.rb

after_everything do
  say_wizard "recipe running after everything"

  # remove default READMEs
  %w{
    README
    README.rdoc
    doc/README_FOR_APP
  }.each { |file| remove_file file }

  # add placeholder READMEs and humans.txt file
  copy_from_repo 'public/humans.txt'
  copy_from_repo 'README'
  copy_from_repo 'README.md'
  gsub_file "README", /App_Name/, "#{app_name.humanize.titleize}"
  gsub_file "README.md", /App_Name/, "#{app_name.humanize.titleize}"

  # Diagnostics
  gsub_file "README.md", /recipes that are known/, "recipes that are NOT known" if diagnostics[:recipes] == 'fail'
  gsub_file "README.md", /preferences that are known/, "preferences that are NOT known" if diagnostics[:prefs] == 'fail'
  print_recipes = recipes.sort.map { |r| "\n* #{r}" }.join('')
  print_preferences = prefs.map { |k, v| "\n* #{k}: #{v}" }.join('')
  gsub_file "README.md", /RECIPES/, print_recipes
  gsub_file "README.md", /PREFERENCES/, print_preferences
  gsub_file "README", /RECIPES/, print_recipes
  gsub_file "README", /PREFERENCES/, print_preferences

  # Ruby on Rails
  gsub_file "README.md", /\* Ruby/, "* Ruby version #{RUBY_VERSION}"
  gsub_file "README.md", /\* Rails/, "* Rails version #{Rails::VERSION::STRING}"

  # Database
  gsub_file "README.md", /SQLite/, "PostgreSQL" if prefer :database, 'postgresql'
  gsub_file "README.md", /SQLite/, "MySQL" if prefer :database, 'mysql'
  gsub_file "README.md", /SQLite/, "MongoDB" if prefer :database, 'mongodb'
  gsub_file "README.md", /ActiveRecord/, "the Mongoid ORM" if prefer :orm, 'mongoid'

  # Template Engine
  gsub_file "README.md", /ERB/, "Haml" if prefer :templates, 'haml'
  gsub_file "README.md", /ERB/, "Slim" if prefer :templates, 'slim'

  # Testing Framework
  gsub_file "README.md", /Test::Unit/, "RSpec" if prefer :unit_test, 'rspec'
  gsub_file "README.md", /RSpec/, "RSpec and Cucumber" if prefer :integration, 'cucumber'
  gsub_file "README.md", /RSpec/, "RSpec and Factory Girl" if prefer :fixtures, 'factory_girl'
  gsub_file "README.md", /RSpec/, "RSpec and Machinist" if prefer :fixtures, 'machinist'

  # Front-end Framework
  gsub_file "README.md", /Front-end Framework: None/, "Front-end Framework: Bootstrap 2.3 (Sass)" if prefer :frontend, 'bootstrap2'
  gsub_file "README.md", /Front-end Framework: None/, "Front-end Framework: Bootstrap 3.0 (Sass)" if prefer :frontend, 'bootstrap3'
  gsub_file "README.md", /Front-end Framework: None/, "Front-end Framework: Zurb Foundation 4" if prefer :frontend, 'foundation4'
  gsub_file "README.md", /Front-end Framework: None/, "Front-end Framework: Zurb Foundation 5" if prefer :frontend, 'foundation5'

  # Form Builder
  gsub_file "README.md", /Form Builder: None/, "Form Builder: SimpleForm" if prefer :form_builder, 'simple_form'

  # Email
  unless prefer :email, 'none'
    gsub_file "README.md", /Gmail/, "SMTP" if prefer :email, 'smtp'
    gsub_file "README.md", /Gmail/, "SendGrid" if prefer :email, 'sendgrid'
    gsub_file "README.md", /Gmail/, "Mandrill" if prefer :email, 'mandrill'
    gsub_file "README.md", /Email delivery is disabled in development./, "Email delivery is configured via MailCatcher in development." if prefer :mailcatcher, true
    insert_into_file 'README.md', "\nEmail rendering in development enabled via MailView.", :after => /Email delivery is.*\n/ if prefer :mail_view, true
  else
    gsub_file "README.md", /Email/, ""
    gsub_file "README.md", /-----/, ""
    gsub_file "README.md", /The application is configured to send email using a Gmail account./, ""
    gsub_file "README.md", /Email delivery is disabled in development./, ""
  end

  # Authentication and Authorization
  gsub_file "README.md", /Authentication: None/, "Authentication: Devise" if prefer :authentication, 'devise'
  gsub_file "README.md", /Authentication: None/, "Authentication: OmniAuth" if prefer :authentication, 'omniauth'
  gsub_file "README.md", /Authorization: None/, "Authorization: CanCan" if prefer :authorization, 'cancan'

  # Admin
  gsub_file "README.md", /Admin: None/, "Admin: ActiveAdmin" if prefer :admin, 'activeadmin'
  gsub_file "README.md", /Admin: None/, "Admin: RailsAdmin" if prefer :admin, 'rails_admin'

  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: add README files"' if prefer :git, true

end # after_everything
# >---------------------------- recipes/readme.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ gems ]----------------------------------<
@current_recipe = "gems"
@before_configs["gems"].call if @before_configs["gems"]
say_recipe 'gems'
@configs[@current_recipe] = config
# >----------------------------- recipes/gems.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/gems.rb

### GEMFILE ###

## Ruby on Rails
insert_into_file('Gemfile', "ruby '#{RUBY_VERSION}'\n", :before => /^ *gem 'rails'/, :force => false)

## Cleanup
# remove the 'sdoc' gem
gsub_file 'Gemfile', /group :doc do/, ''
gsub_file 'Gemfile', /\s*gem 'sdoc', require: false\nend/, ''

assets_group = rails_4? ? nil : :assets

## Web Server
if (prefs[:dev_webserver] == prefs[:prod_webserver])
  add_gem 'thin' if prefer :dev_webserver, 'thin'
  add_gem 'unicorn' if prefer :dev_webserver, 'unicorn'
  add_gem 'unicorn-rails' if prefer :dev_webserver, 'unicorn'
  add_gem 'puma' if prefer :dev_webserver, 'puma'
  add_gem 'passenger' if prefer :dev_webserver, 'passenger_standalone'
else
  add_gem 'thin', :group => [:development, :test] if prefer :dev_webserver, 'thin'
  add_gem 'unicorn', :group => [:development, :test] if prefer :dev_webserver, 'unicorn'
  add_gem 'unicorn-rails', :group => [:development, :test] if prefer :dev_webserver, 'unicorn'
  add_gem 'puma', :group => [:development, :test] if prefer :dev_webserver, 'puma'
  add_gem 'passenger', :group => [:development, :test] if prefer :dev_webserver, 'passenger_standalone'
  add_gem 'thin', :group => :production if prefer :prod_webserver, 'thin'
  add_gem 'unicorn', :group => :production if prefer :prod_webserver, 'unicorn'
  add_gem 'puma', :group => :production if prefer :prod_webserver, 'puma'
  add_gem 'passenger', :group => :production if prefer :prod_webserver, 'passenger_standalone'
end





gsub_file 'Gemfile', /gem 'pg'.*/, ''
add_gem 'pg' 

## Template Engine
if prefer :templates, 'haml'
  add_gem 'haml-rails'
end

## Testing Framework
if prefer :tests, 'rspec'
  add_gem 'rails_apps_testing', :group => :development
  add_gem 'rspec-rails', '>= 3.0.0.beta2', :group => [:development, :test]
  add_gem 'factory_girl_rails', :group => [:development, :test]
  add_gem 'faker', :group => :test
  add_gem 'capybara', :group => :test
  add_gem 'database_cleaner', :group => :test
  add_gem 'launchy', :group => :test
  add_gem 'selenium-webdriver', :group => :test
  if prefer :continuous_testing, 'guard'
    add_gem 'guard-bundler', :group => :development
    add_gem 'guard-rails', :group => :development
    add_gem 'guard-rspec', :group => :development
    add_gem 'rb-inotify', :group => :development, :require => false
    add_gem 'rb-fsevent', :group => :development, :require => false
    add_gem 'rb-fchange', :group => :development, :require => false
  end
end

## Front-end Framework
add_gem 'rails_layout', :group => :development
case prefs[:frontend]
#   when 'bootstrap2'
#     add_gem 'bootstrap-sass', '~> 2.3.2.2'
#   when 'bootstrap3'
#     add_gem 'bootstrap-sass'
#   when 'foundation4'
#     if rails_4?
#       add_gem 'zurb-foundation', '~> 4.3.2'
#       add_gem 'compass-rails', '~> 1.1.2'
#     else
#       add_gem 'zurb-foundation', '~> 4.3.2', :group => assets_group
#       add_gem 'compass-rails', '~> 1.0.3', :group => assets_group
#     end
#   when 'foundation5'
#     add_gem 'foundation-rails'
# end

## Email
add_gem 'sendgrid' if prefer :email, 'sendgrid'

## Authentication (Devise)
add_gem 'devise' if prefer :authentication, 'devise'
add_gem 'devise_invitable' if prefer :devise_modules, 'invitable'

## Authentication (OmniAuth)
add_gem 'omniauth' if prefer :authentication, 'omniauth'
add_gem 'omniauth-twitter' if prefer :omniauth_provider, 'twitter'
add_gem 'omniauth-facebook' if prefer :omniauth_provider, 'facebook'
add_gem 'omniauth-github' if prefer :omniauth_provider, 'github'
add_gem 'omniauth-linkedin' if prefer :omniauth_provider, 'linkedin'
add_gem 'omniauth-google-oauth2' if prefer :omniauth_provider, 'google_oauth2'
add_gem 'omniauth-tumblr' if prefer :omniauth_provider, 'tumblr'


add_gem 'pundit' if prefer :authorization, 'pundit'


## Membership App
if prefer :railsapps, 'rails-stripe-membership-saas'
  add_gem 'stripe'
  add_gem 'stripe_event'
end
if prefer :railsapps, 'rails-recurly-subscription-saas'
  add_gem 'recurly'
  add_gem 'nokogiri'
  add_gem 'countries'
  add_gem 'httpi'
  add_gem 'httpclient'
end

## Signup App
if prefer :railsapps, 'rails-prelaunch-signup'
  add_gem 'gibbon'
  add_gem 'capybara-webkit', :group => :test
end

## Gems from a defaults file or added interactively
gems.each do |g|
  gem(*g)
end

## Git
git :add => '-A'
git :commit => '-qm "rails_apps_composer: Gemfile"'

### CREATE DATABASE ###
after_bundler do
  unless prefer :database, 'default'
    copy_from_repo 'config/database-postgresql.yml', :prefs => 'postgresql'
    copy_from_repo 'config/database-mysql.yml', :prefs => 'mysql'
    generate 'mongoid:config' if prefer :orm, 'mongoid'
    remove_file 'config/database.yml' if prefer :orm, 'mongoid'
    if prefer :database, 'postgresql'
      begin
        pg_username = prefs[:pg_username] || ask_wizard("Username for PostgreSQL?(leave blank to use the app name)")
        pg_host = prefs[:pg_host] || ask_wizard("Host for PostgreSQL in database.yml? (leave blank to use default socket connection)")
        if pg_username.blank?
          say_wizard "Creating a user named '#{app_name}' for PostgreSQL"
          run "createuser --createdb #{app_name}" if prefer :database, 'postgresql'
          gsub_file "config/database.yml", /username: .*/, "username: #{app_name}"
        else
          gsub_file "config/database.yml", /username: .*/, "username: #{pg_username}"
          pg_password = prefs[:pg_password] || ask_wizard("Password for PostgreSQL user #{pg_username}?")
          gsub_file "config/database.yml", /password:/, "password: #{pg_password}"
          say_wizard "set config/database.yml for username/password #{pg_username}/#{pg_password}"
        end
        if pg_host.present?
          gsub_file "config/database.yml", /#host: localhost/, "host: #{pg_host}"
          gsub_file "config/database.yml", /test:/, "test:\n  host: #{pg_host}"
        end
      rescue StandardError => e
        raise "unable to create a user for PostgreSQL, reason: #{e}"
      end
      gsub_file "config/database.yml", /database: myapp_development/, "database: #{app_name}_development"
      gsub_file "config/database.yml", /database: myapp_test/,        "database: #{app_name}_test"
      gsub_file "config/database.yml", /database: myapp_production/,  "database: #{app_name}_production"
    end
    if prefer :database, 'mysql'
      mysql_username = prefs[:mysql_username] || ask_wizard("Username for MySQL? (leave blank to use the app name)")
      if mysql_username.blank?
        gsub_file "config/database.yml", /username: .*/, "username: #{app_name}"
      else
        gsub_file "config/database.yml", /username: .*/, "username: #{mysql_username}"
        mysql_password = prefs[:mysql_password] || ask_wizard("Password for MySQL user #{mysql_username}?")
        gsub_file "config/database.yml", /password:/, "password: #{mysql_password}"
        say_wizard "set config/database.yml for username/password #{mysql_username}/#{mysql_password}"
      end
      gsub_file "config/database.yml", /database: myapp_development/, "database: #{app_name}_development"
      gsub_file "config/database.yml", /database: myapp_test/,        "database: #{app_name}_test"
      gsub_file "config/database.yml", /database: myapp_production/,  "database: #{app_name}_production"
    end
    unless prefer :database, 'sqlite'
      if (prefs.has_key? :drop_database) ? prefs[:drop_database] :
          (yes_wizard? "Okay to drop all existing databases named #{app_name}? 'No' will abort immediately!")
        run 'bundle exec rake db:drop'
      else
        raise "aborted at user's request"
      end
    end
    run 'bundle exec rake db:create:all' unless prefer :orm, 'mongoid'
    run 'bundle exec rake db:create' if prefer :orm, 'mongoid'
    ## Git
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: create database"' if prefer :git, true
  end
end # after_bundler

### GENERATORS ###
after_bundler do
  ## Form Builder
  if prefer :form_builder, 'simple_form'
    case prefs[:frontend]
      when 'bootstrap2'
        say_wizard "recipe installing simple_form for use with Bootstrap"
        generate 'simple_form:install --bootstrap'
      when 'bootstrap3'
        say_wizard "recipe installing simple_form for use with Bootstrap"
        generate 'simple_form:install --bootstrap'
      when 'foundation5'
        say_wizard "recipe installing simple_form for use with Zurb Foundation"
        generate 'simple_form:install --foundation'
      when 'foundation4'
        say_wizard "recipe installing simple_form for use with Zurb Foundation"
        generate 'simple_form:install --foundation'
      else
        say_wizard "recipe installing simple_form"
        generate 'simple_form:install'
    end
  end
  ## Figaro Gem
  if prefer :local_env_file, 'figaro'
    generate 'figaro:install'
    gsub_file 'config/application.yml', /# PUSHER_.*\n/, ''
    gsub_file 'config/application.yml', /# STRIPE_.*\n/, ''
    prepend_to_file 'config/application.yml' do <<-FILE
# Add account credentials and API keys here.
# See http://railsapps.github.io/rails-environment-variables.html
# This file should be listed in .gitignore to keep your settings secret!
# Each entry sets a local environment variable.
# For example, setting:
# GMAIL_USERNAME: Your_Gmail_Username
# makes 'Your_Gmail_Username' available as ENV["GMAIL_USERNAME"]

FILE
    end
  end
  ## Foreman Gem
  if prefer :local_env_file, 'foreman'
    create_file '.env' do <<-FILE
# Add account credentials and API keys here.
# This file should be listed in .gitignore to keep your settings secret!
# Each entry sets a local environment variable.
# For example, setting:
# GMAIL_USERNAME=Your_Gmail_Username
# makes 'Your_Gmail_Username' available as ENV["GMAIL_USERNAME"]

FILE
    end
    create_file 'Procfile', 'web: bundle exec rails server -p $PORT' if prefer :prod_webserver, 'thin'
    create_file 'Procfile', 'web: bundle exec unicorn -p $PORT' if prefer :prod_webserver, 'unicorn'
    create_file 'Procfile', 'web: bundle exec puma -p $PORT' if prefer :prod_webserver, 'puma'
    create_file 'Procfile', 'web: bundle exec passenger start -p $PORT' if prefer :prod_webserver, 'passenger_standalone'
    if (prefs[:dev_webserver] != prefs[:prod_webserver])
      create_file 'Procfile.dev', 'web: bundle exec rails server -p $PORT' if prefer :dev_webserver, 'thin'
      create_file 'Procfile.dev', 'web: bundle exec unicorn -p $PORT' if prefer :dev_webserver, 'unicorn'
      create_file 'Procfile.dev', 'web: bundle exec puma -p $PORT' if prefer :dev_webserver, 'puma'
      create_file 'Procfile.dev', 'web: bundle exec passenger start -p $PORT' if prefer :dev_webserver, 'passenger_standalone'
    end
  end
  ## Git
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: generators"' if prefer :git, true
end # after_bundler
# >----------------------------- recipes/gems.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ testing ]--------------------------------<
@current_recipe = "testing"
@before_configs["testing"].call if @before_configs["testing"]
say_recipe 'testing'
@configs[@current_recipe] = config
# >--------------------------- recipes/testing.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/testing.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### TEST/UNIT ###
  if prefer :unit_test, 'test_unit'
    inject_into_file 'config/application.rb', :after => "Rails::Application\n" do <<-RUBY

    config.generators do |g|
      #{"g.test_framework :test_unit, fixture_replacement: :fabrication" if prefer :fixtures, 'fabrication'}
      #{"g.fixture_replacement :fabrication, dir: 'test/fabricators'" if prefer :fixtures, 'fabrication'}
    end

RUBY
    end
  end
  ### RSPEC ###
  if prefer :unit_test, 'rspec'
    say_wizard "recipe installing RSpec"
    generate 'rspec:install'
    copy_from_repo 'spec/spec_helper.rb', :repo => 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/'
    generate 'email_spec:steps' if prefer :integration, 'cucumber'
    inject_into_file 'spec/spec_helper.rb', "require 'email_spec'\n", :after => "require 'rspec/rails'\n"
    inject_into_file 'spec/spec_helper.rb', :after => "RSpec.configure do |config|\n" do <<-RUBY
  config.include(EmailSpec::Helpers)
  config.include(EmailSpec::Matchers)
RUBY
    end
    run 'rm -rf test/' # Removing test folder (not needed for RSpec)
    inject_into_file 'config/application.rb', :after => "Rails::Application\n" do <<-RUBY

    # don't generate RSpec tests for views and helpers
    config.generators do |g|
      #{"g.test_framework :rspec" if prefer :fixtures, 'none'}
      #{"g.test_framework :rspec, fixture: true" unless prefer :fixtures, 'none'}
      #{"g.fixture_replacement :factory_girl, dir: 'spec/factories'" if prefer :fixtures, 'factory_girl'}
      #{"g.fixture_replacement :machinist" if prefer :fixtures, 'machinist'}
      #{"g.fixture_replacement :fabrication" if prefer :fixtures, 'fabrication'}
      g.view_specs false
      g.helper_specs false
    end

RUBY
    end
    ## RSPEC AND MONGOID
    if prefer :orm, 'mongoid'
      # remove ActiveRecord artifacts
      gsub_file 'spec/spec_helper.rb', /config.fixture_path/, '# config.fixture_path'
      gsub_file 'spec/spec_helper.rb', /config.use_transactional_fixtures/, '# config.use_transactional_fixtures'
      # remove either possible occurrence of "require rails/test_unit/railtie"
      gsub_file 'config/application.rb', /require 'rails\/test_unit\/railtie'/, '# require "rails/test_unit/railtie"'
      gsub_file 'config/application.rb', /require "rails\/test_unit\/railtie"/, '# require "rails/test_unit/railtie"'
      # configure RSpec to use matchers from the mongoid-rspec gem
      create_file 'spec/support/mongoid.rb' do
      <<-RUBY
RSpec.configure do |config|
  config.include Mongoid::Matchers
end
RUBY
      end
    end
    ## RSPEC AND DEVISE
    if prefer :authentication, 'devise'
      # add Devise test helpers
      create_file 'spec/support/devise.rb' do
      <<-RUBY
RSpec.configure do |config|
  config.include Devise::TestHelpers, :type => :controller
end
RUBY
      end
    end
  end
  ### CUCUMBER ###
  if prefer :integration, 'cucumber'
    say_wizard "recipe installing Cucumber"
    generate "cucumber:install --capybara#{' --rspec' if prefer :unit_test, 'rspec'}#{' -D' if prefer :orm, 'mongoid'}"
    # make it easy to run Cucumber for single features without adding "--require features" to the command line
    gsub_file 'config/cucumber.yml', /std_opts = "/, 'std_opts = "-r features/support/ -r features/step_definitions '
    create_file 'features/support/email_spec.rb' do <<-RUBY
require 'email_spec/cucumber'
RUBY
    end
    ## CUCUMBER AND MONGOID
    if prefer :orm, 'mongoid'
      gsub_file 'features/support/env.rb', /transaction/, "truncation"
      inject_into_file 'features/support/env.rb', :after => 'begin' do
        "\n  DatabaseCleaner.orm = 'mongoid'"
      end
    end
    generate 'fabrication:cucumber_steps' if prefer :fixtures, 'fabrication'
  end
  ## TURNIP
  if prefer :integration, 'turnip'
    append_file '.rspec', '-r turnip/rspec'
    inject_into_file 'spec/spec_helper.rb', "require 'turnip/capybara'\n", :after => "require 'rspec/rails'\n"
    create_file 'spec/acceptance/steps/.gitkeep'
  end
  ## FIXTURE REPLACEMENTS
  if prefer :fixtures, 'machinist'
    say_wizard "generating blueprints file for 'machinist'"
    generate 'machinist:install'
  end
  ### GUARD
  if prefer :continuous_testing, 'guard'
    say_wizard "recipe initializing Guard"
    run 'bundle exec guard init'
  end
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: testing framework"' if prefer :git, true
end # after_bundler

after_everything do
  say_wizard "recipe running after everything"
  ### RSPEC ###
  if prefer :unit_test, 'rspec'
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'users_app')
      say_wizard "copying RSpec files from the rails3-devise-rspec-cucumber examples"
      repo = 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/'
      copy_from_repo 'spec/factories/users.rb', :repo => repo
      gsub_file 'spec/factories/users.rb', /# confirmed_at/, "confirmed_at" if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/controllers/users_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/models/user_spec.rb', :repo => repo
      remove_file 'spec/views/home/index.html.erb_spec.rb'
      remove_file 'spec/views/home/index.html.haml_spec.rb'
      remove_file 'spec/views/users/show.html.erb_spec.rb'
      remove_file 'spec/views/users/show.html.haml_spec.rb'
      remove_file 'spec/helpers/home_helper_spec.rb'
      remove_file 'spec/helpers/users_helper_spec.rb'
    end
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'admin_app')
      say_wizard "copying RSpec files from the rails3-bootstrap-devise-cancan examples"
      repo = 'https://raw.github.com/RailsApps/rails3-bootstrap-devise-cancan/master/'
      copy_from_repo 'spec/factories/users.rb', :repo => repo
      gsub_file 'spec/factories/users.rb', /# confirmed_at/, "confirmed_at" if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/controllers/users_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/models/user_spec.rb', :repo => repo
      remove_file 'spec/views/home/index.html.erb_spec.rb'
      remove_file 'spec/views/home/index.html.haml_spec.rb'
      remove_file 'spec/views/users/show.html.erb_spec.rb'
      remove_file 'spec/views/users/show.html.haml_spec.rb'
      remove_file 'spec/helpers/home_helper_spec.rb'
      remove_file 'spec/helpers/users_helper_spec.rb'
    end
    ## RSPEC AND OMNIAUTH
    if (prefer :authentication, 'omniauth') && (prefer :starter_app, 'users_app')
      say_wizard "copying RSpec files from the rails3-mongoid-omniauth examples"
      repo = 'https://raw.github.com/RailsApps/rails3-mongoid-omniauth/master/'
      copy_from_repo 'spec/factories/users.rb', :repo => repo
      copy_from_repo 'spec/controllers/sessions_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/controllers/users_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/models/user_spec.rb', :repo => repo
    end
    ## SUBDOMAINS
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'subdomains_app')
      say_wizard "copying RSpec files from the rails3-subdomains examples"
      repo = 'https://raw.github.com/RailsApps/rails3-subdomains/master/'
      copy_from_repo 'spec/factories/users.rb', :repo => repo
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/controllers/users_controller_spec.rb', :repo => repo
      copy_from_repo 'spec/models/user_spec.rb', :repo => repo
    end
    ## GIT
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: rspec files"' if prefer :git, true
  end
  ### CUCUMBER ###
  if prefer :integration, 'cucumber'
    ## CUCUMBER AND DEVISE (USERS APP)
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'users_app')
      say_wizard "copying Cucumber scenarios from the rails3-devise-rspec-cucumber examples"
      repo = 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/'
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'features/users/sign_in.feature', :repo => repo
      copy_from_repo 'features/users/sign_out.feature', :repo => repo
      copy_from_repo 'features/users/sign_up.feature', :repo => repo
      copy_from_repo 'features/users/user_edit.feature', :repo => repo
      copy_from_repo 'features/users/user_show.feature', :repo => repo
      copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
      copy_from_repo 'features/support/paths.rb', :repo => repo
      if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
        gsub_file 'features/step_definitions/user_steps.rb', /Welcome! You have signed up successfully./, "A message with a confirmation link has been sent to your email address."
        inject_into_file 'features/users/sign_in.feature', :before => '    Scenario: User signs in successfully' do
<<-RUBY
  Scenario: User has not confirmed account
    Given I exist as an unconfirmed user
    And I am not logged in
    When I sign in with valid credentials
    Then I see an unconfirmed account message
    And I should be signed out
RUBY
        end
      end
    end
    ## CUCUMBER AND DEVISE (ADMIN APP)
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'admin_app')
      say_wizard "copying Cucumber scenarios from the rails3-bootstrap-devise-cancan examples"
      repo = 'https://raw.github.com/RailsApps/rails3-bootstrap-devise-cancan/master/'
      copy_from_repo 'spec/controllers/home_controller_spec.rb', :repo => repo
      copy_from_repo 'features/users/sign_in.feature', :repo => repo
      copy_from_repo 'features/users/sign_out.feature', :repo => repo
      copy_from_repo 'features/users/sign_up.feature', :repo => repo
      copy_from_repo 'features/users/user_edit.feature', :repo => repo
      copy_from_repo 'features/users/user_show.feature', :repo => repo
      copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
      copy_from_repo 'features/support/paths.rb', :repo => repo
      if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
        gsub_file 'features/step_definitions/user_steps.rb', /Welcome! You have signed up successfully./, "A message with a confirmation link has been sent to your email address."
        inject_into_file 'features/users/sign_in.feature', :before => '    Scenario: User signs in successfully' do
<<-RUBY
  Scenario: User has not confirmed account
    Given I exist as an unconfirmed user
    And I am not logged in
    When I sign in with valid credentials
    Then I see an unconfirmed account message
    And I should be signed out
RUBY
        end
      end
    end
    ## CUCUMBER AND DEVISE (SUBDOMAINS APP)
    if (prefer :authentication, 'devise') && (prefer :starter_app, 'subdomains_app')
      say_wizard "copying RSpec files from the rails3-subdomains examples"
      repo = 'https://raw.github.com/RailsApps/rails3-subdomains/master/'
      copy_from_repo 'features/users/sign_in.feature', :repo => repo
      copy_from_repo 'features/users/sign_out.feature', :repo => repo
      copy_from_repo 'features/users/sign_up.feature', :repo => repo
      copy_from_repo 'features/users/user_edit.feature', :repo => repo
      copy_from_repo 'features/users/user_show.feature', :repo => repo
      copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
      copy_from_repo 'features/support/paths.rb', :repo => repo
    end
    ## GIT
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: cucumber files"' if prefer :git, true
  end
  ### FABRICATION ###
  if prefer :fixtures, 'fabrication'
    say_wizard "replacing FactoryGirl fixtures with Fabrication"
    remove_file 'spec/factories/users.rb'
    remove_file 'spec/fabricators/user_fabricator.rb'
    create_file 'spec/fabricators/user_fabricator.rb' do
      <<-RUBY
Fabricator(:user) do
  name     'Test User'
  email    'example@example.com'
  password 'changeme'
  password_confirmation 'changeme'
  # required if the Devise Confirmable module is used
  # confirmed_at Time.now
end
RUBY
    end
    if prefer :integration, 'cucumber'
      gsub_file 'features/step_definitions/user_steps.rb', /@user = FactoryGirl.create\(:user, email: @visitor\[:email\]\)/, '@user = Fabricate(:user, email: @visitor[:email])'
    end
    if File.exist?('spec/controllers/users_controller_spec.rb')
      gsub_file 'spec/controllers/users_controller_spec.rb', /@user = FactoryGirl.create\(:user\)/, '@user = Fabricate(:user)'
    end
  end
end # after_everything
# >--------------------------- recipes/testing.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ tests4 ]---------------------------------<
@current_recipe = "tests4"
@before_configs["tests4"].call if @before_configs["tests4"]
say_recipe 'tests4'
@configs[@current_recipe] = config
# >---------------------------- recipes/tests4.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/tests4.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### RSPEC ###
  if prefer :tests, 'rspec'
    say_wizard "recipe installing RSpec"
    generate 'testing:configure rspec -f'
  end
  ### GUARD ###
  if prefer :continuous_testing, 'guard'
    say_wizard "recipe initializing Guard"
    run 'bundle exec guard init'
  end
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: testing framework"' if prefer :git, true
end # after_bundler

after_everything do
  say_wizard "recipe running after everything"
  if prefer :authentication, 'devise'
    generate 'testing:configure devise -f'
  end
end # after_everything
# >---------------------------- recipes/tests4.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ email ]---------------------------------<
@current_recipe = "email"
@before_configs["email"].call if @before_configs["email"]
say_recipe 'email'
@configs[@current_recipe] = config
# >---------------------------- recipes/email.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/email.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  unless prefer :email, 'none'
    if rails_4?
      dev_email_text = <<-TEXT
  # ActionMailer Config
  config.action_mailer.default_url_options = { :host => 'localhost:3000' }
  config.action_mailer.delivery_method = :smtp
  config.action_mailer.raise_delivery_errors = true
  # Send email in development mode?
  config.action_mailer.perform_deliveries = true
TEXT
      prod_email_text = <<-TEXT
  # ActionMailer Config
  config.action_mailer.default_url_options = { :host => 'example.com' }
  config.action_mailer.delivery_method = :smtp
  config.action_mailer.perform_deliveries = true
  config.action_mailer.raise_delivery_errors = false
TEXT
      inject_into_file 'config/environments/development.rb', dev_email_text, :after => "config.assets.debug = true"
      inject_into_file 'config/environments/production.rb', prod_email_text, :after => "config.active_support.deprecation = :notify"
      gsub_file 'config/environments/production.rb', /'example.com'/, 'Rails.application.secrets.domain_name' if rails_4_1?

    else
      ### DEVELOPMENT
      gsub_file 'config/environments/development.rb', /# Don't care if the mailer can't send/, '# ActionMailer Config'
      gsub_file 'config/environments/development.rb', /config.action_mailer.raise_delivery_errors = false/ do
  <<-RUBY
config.action_mailer.default_url_options = { :host => 'localhost:3000' }
  config.action_mailer.delivery_method = :smtp
  # change to true to allow email to be sent during development
  config.action_mailer.perform_deliveries = false
  config.action_mailer.raise_delivery_errors = true
  config.action_mailer.default :charset => "utf-8"
RUBY
      end
      ### TEST
      inject_into_file 'config/environments/test.rb', :before => "\nend" do
  <<-RUBY
\n
  # ActionMailer Config
  config.action_mailer.default_url_options = { :host => 'example.com' }
RUBY
      end
      ### PRODUCTION
      gsub_file 'config/environments/production.rb', /config.active_support.deprecation = :notify/ do
  <<-RUBY
config.active_support.deprecation = :notify

  config.action_mailer.default_url_options = { :host => 'example.com' }
  # ActionMailer Config
  # Setup for production - deliveries, no errors raised
  config.action_mailer.delivery_method = :smtp
  config.action_mailer.perform_deliveries = true
  config.action_mailer.raise_delivery_errors = false
  config.action_mailer.default :charset => "utf-8"
RUBY
      end
    end
    if rails_4_1?
      email_configuration_text = <<-TEXT
\n
  config.action_mailer.smtp_settings = {
    address: "smtp.gmail.com",
    port: 587,
    domain: Rails.application.secrets.domain_name,
    authentication: "plain",
    enable_starttls_auto: true,
    user_name: Rails.application.secrets.email_provider_username,
    password: Rails.application.secrets.email_provider_password
  }
TEXT
      inject_into_file 'config/environments/development.rb', email_configuration_text, :after => "config.assets.debug = true"
      inject_into_file 'config/environments/production.rb', email_configuration_text, :after => "config.active_support.deprecation = :notify"
      case :email
        when 'sendgrid'
          gsub_file 'config/environments/development.rb', /smtp.gmail.com/, 'smtp.sendgrid.net'
          gsub_file 'config/environments/production.rb', /smtp.gmail.com/, 'smtp.sendgrid.net'
        when 'mandrill'
          gsub_file 'config/environments/development.rb', /smtp.gmail.com/, 'smtp.mandrillapp.com'
          gsub_file 'config/environments/production.rb', /smtp.gmail.com/, 'smtp.mandrillapp.com'
          gsub_file 'config/environments/development.rb', /email_provider_password/, 'email_provider_apikey'
          gsub_file 'config/environments/production.rb', /email_provider_password/, 'email_provider_apikey'
      end
    else
      ### GMAIL ACCOUNT
      if prefer :email, 'gmail'
        gmail_configuration_text = <<-TEXT
\n
  config.action_mailer.smtp_settings = {
    address: "smtp.gmail.com",
    port: 587,
    domain: ENV["DOMAIN_NAME"],
    authentication: "plain",
    enable_starttls_auto: true,
    user_name: ENV["GMAIL_USERNAME"],
    password: ENV["GMAIL_PASSWORD"]
  }
TEXT
        inject_into_file 'config/environments/development.rb', gmail_configuration_text, :after => "config.assets.debug = true"
        inject_into_file 'config/environments/production.rb', gmail_configuration_text, :after => "config.active_support.deprecation = :notify"
      end
      ### SENDGRID ACCOUNT
      if prefer :email, 'sendgrid'
        sendgrid_configuration_text = <<-TEXT
\n
  config.action_mailer.smtp_settings = {
    address: "smtp.sendgrid.net",
    port: 587,
    domain: ENV["DOMAIN_NAME"],
    authentication: "plain",
    user_name: ENV["SENDGRID_USERNAME"],
    password: ENV["SENDGRID_PASSWORD"]
  }
TEXT
        inject_into_file 'config/environments/development.rb', sendgrid_configuration_text, :after => "config.assets.debug = true"
        inject_into_file 'config/environments/production.rb', sendgrid_configuration_text, :after => "config.active_support.deprecation = :notify"
      end
      ### MANDRILL ACCOUNT
      if prefer :email, 'mandrill'
        mandrill_configuration_text = <<-TEXT
\n
  config.action_mailer.smtp_settings = {
    :address   => "smtp.mandrillapp.com",
    :port      => 587,
    :user_name => ENV["MANDRILL_USERNAME"],
    :password  => ENV["MANDRILL_APIKEY"]
  }
TEXT
        inject_into_file 'config/environments/development.rb', mandrill_configuration_text, :after => "config.assets.debug = true"
        inject_into_file 'config/environments/production.rb', mandrill_configuration_text, :after => "config.active_support.deprecation = :notify"
      end
    end
  end
  ### GIT
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: set email accounts"' if prefer :git, true
end # after_bundler
# >---------------------------- recipes/email.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ models ]---------------------------------<
@current_recipe = "models"
@before_configs["models"].call if @before_configs["models"]
say_recipe 'models'
@configs[@current_recipe] = config
# >---------------------------- recipes/models.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/models.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### DEVISE ###
  if prefer :authentication, 'devise'
    # prevent logging of password_confirmation
    gsub_file 'config/application.rb', /:password/, ':password, :password_confirmation'
    generate 'devise:install'
    generate 'devise_invitable:install' if prefer :devise_modules, 'invitable'
    generate 'devise user' # create the User model
    if prefer :orm, 'mongoid'
      ## DEVISE AND MONGOID
      copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails3-mongoid-devise/master/' unless rails_4?
      if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
        gsub_file 'app/models/user.rb', /:registerable,/, ":registerable, :confirmable,"
        gsub_file 'app/models/user.rb', /# field :confirmation_token/, "field :confirmation_token"
        gsub_file 'app/models/user.rb', /# field :confirmed_at/, "field :confirmed_at"
        gsub_file 'app/models/user.rb', /# field :confirmation_sent_at/, "field :confirmation_sent_at"
        gsub_file 'app/models/user.rb', /# field :unconfirmed_email/, "field :unconfirmed_email"
      end
      if (prefer :devise_modules, 'invitable')
        gsub_file 'app/models/user.rb', /\bend\s*\Z/ do
  <<-RUBY
  #invitable
  field :invitation_token, :type => String
  field :invitation_sent_at, :type => Time
  field :invitation_accepted_at, :type => Time
  field :invitation_limit, :type => Integer
  field :invited_by_id, :type => String
  field :invited_by_type, :type => String
end
RUBY
        end
      end
    else
      ## DEVISE AND ACTIVE RECORD
      unless prefer :railsapps, 'rails-recurly-subscription-saas'
        generate 'migration AddNameToUsers name:string'
      end
      copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/' unless rails_4?
      if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
        gsub_file 'app/models/user.rb', /:registerable,/, ":registerable, :confirmable,"
        generate 'migration AddConfirmableToUsers confirmation_token:string confirmed_at:datetime confirmation_sent_at:datetime unconfirmed_email:string'
      end
    end
    ## DEVISE AND CUCUMBER
    if prefer :integration, 'cucumber'
      # Cucumber wants to test GET requests not DELETE requests for destroy_user_session_path
      # (see https://github.com/RailsApps/rails3-devise-rspec-cucumber/issues/3)
      gsub_file 'config/initializers/devise.rb', 'config.sign_out_via = :delete', 'config.sign_out_via = Rails.env.test? ? :get : :delete'
    end
  end
  ### OMNIAUTH ###
  if prefer :authentication, 'omniauth'
    copy_from_repo 'config/initializers/omniauth.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
    gsub_file 'config/initializers/omniauth.rb', /twitter/, prefs[:omniauth_provider] unless prefer :omniauth_provider, 'twitter'
    if prefer :orm, 'mongoid'
      copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails3-mongoid-omniauth/master/'
    else
      generate 'model User name:string email:string provider:string uid:string'
      run 'bundle exec rake db:migrate'
      copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
    end
  end
  ### SUBDOMAINS ###
  copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/' if prefer :starter_app, 'subdomains_app'
  ### AUTHORIZATION ###
  if prefer :authorization, 'pundit'
    generate 'migration AddRoleToUsers role:integer'
    copy_from_repo 'app/models/user.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
    if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
      gsub_file 'app/models/user.rb', /:registerable,/, ":registerable, :confirmable,"
      generate 'migration AddConfirmableToUsers confirmation_token:string confirmed_at:datetime confirmation_sent_at:datetime unconfirmed_email:string'
    end
  end
  if prefer :authorization, 'cancan'
    generate 'cancan:ability'
    if prefer :starter_app, 'admin_app'
      # Limit access to the users#index page
      copy_from_repo 'app/models/ability.rb', :repo => 'https://raw.github.com/RailsApps/rails3-bootstrap-devise-cancan/master/'
      # allow an admin to update roles
      insert_into_file 'app/models/user.rb', "  attr_accessible :role_ids, :as => :admin\n", :before => "  attr_accessible"
    end
    unless prefer :orm, 'mongoid'
      generate 'rolify Role User'
    else
      generate 'rolify Role User --orm=mongoid'
    end
  end
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: models"' if prefer :git, true
end # after_bundler
# >---------------------------- recipes/models.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >------------------------------[ controllers ]------------------------------<
@current_recipe = "controllers"
@before_configs["controllers"].call if @before_configs["controllers"]
say_recipe 'controllers'
@configs[@current_recipe] = config
# >------------------------- recipes/controllers.rb --------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/controllers.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### APPLICATION_CONTROLLER ###
  if prefer :authentication, 'omniauth'
    copy_from_repo 'app/controllers/application_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
  end
  if prefer :authorization, 'pundit'
    copy_from_repo 'app/controllers/application_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
  end
  if prefer :authorization, 'cancan'
    inject_into_file 'app/controllers/application_controller.rb', :before => "\nend" do <<-RUBY
\n
  rescue_from CanCan::AccessDenied do |exception|
    redirect_to root_path, :alert => exception.message
  end
RUBY
    end
  end
  ### HOME_CONTROLLER ###
  if ['home_app','users_app','admin_app','subdomains_app'].include? prefs[:starter_app]
    generate 'controller home --skip-assets --skip-helper'
  end
  ### USERS_CONTROLLER ###
  case prefs[:starter_app]
    when 'users_app'
      if (prefer :authentication, 'devise') and (not prefer :apps4, 'rails-devise')
        copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/'
      elsif prefer :authentication, 'omniauth'
        if rails_4?
          copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
        else
          copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-mongoid-omniauth/master/'
        end
      end
    when 'admin_app'
      if (prefer :authentication, 'devise') and (not prefer :apps4, 'rails-devise')
        copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-bootstrap-devise-cancan/master/'
      elsif prefer :authentication, 'omniauth'
        if rails_4?
          copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
        else
          copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-mongoid-omniauth/master/'
        end
      end
      if prefer :authorization, 'pundit'
        copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
        copy_from_repo 'app/policies/user_policy.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
      end
    when 'subdomains_app'
      copy_from_repo 'app/controllers/users_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/'
  end
  ### REGISTRATIONS_CONTROLLER ###
  if rails_4?
    if ['users_app','admin_app','subdomains_app'].include? prefs[:starter_app]
      ## accommodate strong parameters in Rails 4
      copy_from_repo 'app/controllers/registrations_controller-devise.rb', :prefs => 'devise'
    end
  end
  ### SESSIONS_CONTROLLER ###
  if prefer :authentication, 'omniauth'
    filename = 'app/controllers/sessions_controller.rb'
    copy_from_repo filename, :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
    gsub_file filename, /twitter/, prefs[:omniauth_provider] unless prefer :omniauth_provider, 'twitter'
    if prefer :authorization, 'cancan'
      inject_into_file filename, "    user.add_role :admin if User.count == 1 # make the first user an admin\n", :after => "session[:user_id] = user.id\n"
    end
  end
  ### PROFILES_CONTROLLER ###
  copy_from_repo 'app/controllers/profiles_controller.rb', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/' if prefer :starter_app, 'subdomains_app'
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: controllers"' if prefer :git, true
end # after_bundler
# >------------------------- recipes/controllers.rb --------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ views ]---------------------------------<
@current_recipe = "views"
@before_configs["views"].call if @before_configs["views"]
say_recipe 'views'
@configs[@current_recipe] = config
# >---------------------------- recipes/views.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/views.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### DEVISE ###
  if (prefer :authentication, 'devise') and (not prefer :apps4, 'rails-devise')
    copy_from_repo 'app/views/devise/shared/_links.html.erb'
    unless prefer :form_builder, 'simple_form'
      copy_from_repo 'app/views/devise/registrations/edit.html.erb'
      copy_from_repo 'app/views/devise/registrations/new.html.erb'
    else
      copy_from_repo 'app/views/devise/registrations/edit-simple_form.html.erb', :prefs => 'simple_form'
      copy_from_repo 'app/views/devise/registrations/new-simple_form.html.erb', :prefs => 'simple_form'
      copy_from_repo 'app/views/devise/sessions/new-simple_form.html.erb', :prefs => 'simple_form'
      copy_from_repo 'app/helpers/application_helper-simple_form.rb', :prefs => 'simple_form'
    end
  end
  ### HOME ###
  copy_from_repo 'app/views/home/index.html.erb' if prefer :starter_app, 'users_app'
  copy_from_repo 'app/views/home/index.html.erb' if prefer :starter_app, 'admin_app'
  copy_from_repo 'app/views/home/index-subdomains_app.html.erb', :prefs => 'subdomains_app'
  ### USERS ###
  if ['users_app','admin_app','subdomains_app'].include? prefs[:starter_app]
    ## INDEX
    if prefer :starter_app, 'admin_app'
      copy_from_repo 'app/views/users/index-admin_app.html.erb', :prefs => 'admin_app'
      unless prefer :form_builder, 'simple_form'
        copy_from_repo 'app/views/users/_user.html.erb'
      else
        copy_from_repo 'app/views/users/_user-simple_form.html.erb', :prefs => 'simple_form'
      end
    else
      copy_from_repo 'app/views/users/index.html.erb'
    end
    ## SHOW
    copy_from_repo 'app/views/users/show.html.erb'
    copy_from_repo 'app/views/users/show-subdomains_app.html.erb', :prefs => 'subdomains_app'
    ## EDIT
    if prefer :authentication, 'omniauth'
      copy_from_repo 'app/views/users/edit.html.erb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
    end
  end
  if (prefer :authorization, 'pundit') and  (prefer :starter_app, 'admin_app')
    repo = 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
    copy_from_repo 'app/views/users/_user.html.erb', :repo => repo
    copy_from_repo 'app/views/users/index.html.erb', :repo => repo
    copy_from_repo 'app/views/users/show.html.erb', :repo => repo
  end
  ### PROFILES ###
  copy_from_repo 'app/views/profiles/show-subdomains_app.html.erb', :prefs => 'subdomains_app'
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: views"' if prefer :git, true
end # after_bundler
# >---------------------------- recipes/views.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ routes ]---------------------------------<
@current_recipe = "routes"
@before_configs["routes"].call if @before_configs["routes"]
say_recipe 'routes'
@configs[@current_recipe] = config
# >---------------------------- recipes/routes.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/routes.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  ### HOME ###
  if prefer :starter_app, 'home_app'
    remove_file 'public/index.html'
    gsub_file 'config/routes.rb', /get \"home\/index\"/, 'root :to => "home#index"'
  end
  ### USER_ACCOUNTS ###
  if ['users_app','admin_app'].include? prefs[:starter_app]
    ## DEVISE
    if (prefer :authentication, 'devise') and (not prefer :apps4, 'rails-devise')
      copy_from_repo 'config/routes.rb', :repo => 'https://raw.github.com/RailsApps/rails3-devise-rspec-cucumber/master/'
      ## Rails 4.0 doesn't allow two 'root' routes
      gsub_file 'config/routes.rb', /authenticated :user do\n.*\n.*\n  /, '' if rails_4?
      ## accommodate strong parameters in Rails 4
      gsub_file 'config/routes.rb', /devise_for :users/, 'devise_for :users, :controllers => {:registrations => "registrations"}' if rails_4?
    end
    ## OMNIAUTH
    if prefer :authentication, 'omniauth'
      if rails_4?
        copy_from_repo 'config/routes.rb', :repo => 'https://raw.github.com/RailsApps/rails-omniauth/master/'
      else
        copy_from_repo 'config/routes.rb', :repo => 'https://raw.github.com/RailsApps/rails3-mongoid-omniauth/master/'
      end
    end
  end
  ### SUBDOMAINS ###
  copy_from_repo 'lib/subdomain.rb', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/' if prefer :starter_app, 'subdomains_app'
  copy_from_repo 'config/routes.rb', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/' if prefer :starter_app, 'subdomains_app'
  ### CORRECT APPLICATION NAME ###
  gsub_file 'config/routes.rb', /^.*.routes.draw do/, "#{app_const}.routes.draw do"
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: routes"' if prefer :git, true
end # after_bundler
# >---------------------------- recipes/routes.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >-------------------------------[ frontend ]--------------------------------<
@current_recipe = "frontend"
@before_configs["frontend"].call if @before_configs["frontend"]
say_recipe 'frontend'
@configs[@current_recipe] = config
# >--------------------------- recipes/frontend.rb ---------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/frontend.rb

after_bundler do
  say_wizard "recipe running after 'bundle install'"
  # set up a front-end framework using the rails_layout gem
  case prefs[:frontend]
    when 'simple'
      generate 'layout:install simple -f'
    when 'bootstrap2'
      generate 'layout:install bootstrap2 -f'
    when 'bootstrap3'
      generate 'layout:install bootstrap3 -f'
    when 'foundation4'
      generate 'layout:install foundation4 -f'
    when 'foundation5'
      generate 'layout:install foundation5 -f'
  end

  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: front-end framework"' if prefer :git, true
end # after_bundler
# >--------------------------- recipes/frontend.rb ---------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ init ]----------------------------------<
@current_recipe = "init"
@before_configs["init"].call if @before_configs["init"]
say_recipe 'init'
@configs[@current_recipe] = config
# >----------------------------- recipes/init.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/init.rb

after_everything do
  say_wizard "recipe running after everything"
  case prefs[:email]
    when 'none'
      secrets_email = foreman_email = ''
    when 'smtp'
      secrets_email = foreman_email = ''
    when 'gmail'
      secrets_email = "  email_provider_username: <%= ENV[\"GMAIL_USERNAME\"] %>\n  email_provider_password: <%= ENV[\"GMAIL_PASSWORD\"] %>\n  domain_name: example.com %>"
       foreman_email = "GMAIL_USERNAME=Your_Username\nGMAIL_PASSWORD=Your_Password\nDOMAIN_NAME=example.com\n"
    when 'sendgrid'
      secrets_email = "  email_provider_username: <%= ENV[\"SENDGRID_USERNAME\"] %>\n  email_provider_password: <%= ENV[\"SENDGRID_PASSWORD\"] %>\n  domain_name: example.com %>"
      foreman_email = "SENDGRID_USERNAME=Your_Username\nSENDGRID_PASSWORD=Your_Password\nDOMAIN_NAME=example.com\n"
    when 'mandrill'
      secrets_email = "  email_provider_username: <%= ENV[\"MANDRILL_USERNAME\"] %>\n  email_provider_apikey: <%= ENV[\"MANDRILL_APIKEY\"] %>\n  domain_name: example.com %>"
      foreman_email = "MANDRILL_USERNAME=Your_Username\nMANDRILL_APIKEY=Your_API_Key\nDOMAIN_NAME=example.com\n"
  end
  figaro_email  = foreman_email.gsub('=', ': ')
  secrets_d_devise = "  admin_name: First User\n  admin_email: user@example.com\n  admin_password: changeme"
  secrets_p_devise = "  admin_name: <%= ENV[\"ADMIN_NAME\"] %>\n  admin_email: <%= ENV[\"ADMIN_EMAIL\"] %>\n  admin_password: <%= ENV[\"ADMIN_PASSWORD\"] %>"
  foreman_devise = "ADMIN_NAME=First User\nADMIN_EMAIL=user@example.com\nADMIN_PASSWORD=changeme\n"
  figaro_devise  = foreman_devise.gsub('=', ': ')
  secrets_omniauth = "  omniauth_provider_key: <%= ENV[\"OMNIAUTH_PROVIDER_KEY\"] %>\n  omniauth_provider_secret: <%= ENV[\"OMNIAUTH_PROVIDER_SECRET\"] %>"
  foreman_omniauth = "OMNIAUTH_PROVIDER_KEY: Your_Provider_Key\nOMNIAUTH_PROVIDER_SECRET: Your_Provider_Secret\n"
  figaro_omniauth  = foreman_omniauth.gsub('=', ': ')
  secrets_cancan = "  roles: <%= ENV[\"ROLES\"] %>" # unnecessary? CanCan will not be used with Rails 4.1?
  foreman_cancan = "ROLES=[admin, user, VIP]\n\n"
  figaro_cancan = foreman_cancan.gsub('=', ': ')
  ## EMAIL
  inject_into_file 'config/secrets.yml', "\n" + secrets_email, :after => "development:" if rails_4_1?
  ### 'inject_into_file' doesn't let us inject the same text twice unless we append the extra space, why?
  inject_into_file 'config/secrets.yml', "\n" + secrets_email + " ", :after => "production:" if rails_4_1?
  append_file '.env', foreman_email if prefer :local_env_file, 'foreman'
  append_file 'config/application.yml', figaro_email if prefer :local_env_file, 'figaro'
  ## DEVISE
  if prefer :authentication, 'devise'
    inject_into_file 'config/secrets.yml', "\n" + secrets_d_devise, :after => "development:" if rails_4_1?
    inject_into_file 'config/secrets.yml', "\n" + secrets_p_devise, :after => "production:" if rails_4_1?
    append_file '.env', foreman_devise if prefer :local_env_file, 'foreman'
    append_file 'config/application.yml', figaro_devise if prefer :local_env_file, 'figaro'
  end
  ## OMNIAUTH
  if prefer :authentication, 'omniauth'
    inject_into_file 'config/secrets.yml', "\n" + secrets_omniauth, :after => "development:" if rails_4_1?
    ### 'inject_into_file' doesn't let us inject the same text twice unless we append the extra space, why?
    inject_into_file 'config/secrets.yml', "\n" + secrets_omniauth + " ", :after => "production:" if rails_4_1?
    append_file '.env', foreman_omniauth if prefer :local_env_file, 'foreman'
    append_file 'config/application.yml', figaro_omniauth if prefer :local_env_file, 'figaro'
  end
  ## CANCAN
  if (prefer :authorization, 'cancan')
    inject_into_file 'config/secrets.yml', "\n" + secrets_cancan, :after => "development:" if rails_4_1?
    ### 'inject_into_file' doesn't let us inject the same text twice unless we append the extra space, why?
    inject_into_file 'config/secrets.yml', "\n" + secrets_cancan + " ", :after => "production:" if rails_4_1?
    append_file '.env', foreman_cancan if prefer :local_env_file, 'foreman'
    append_file 'config/application.yml', figaro_cancan if prefer :local_env_file, 'figaro'
  end
  ### SUBDOMAINS (FIGARO ONLY) ###
  copy_from_repo 'config/application.yml', :repo => 'https://raw.github.com/RailsApps/rails3-subdomains/master/' if prefer :starter_app, 'subdomains_app'
  ### EXAMPLE FILE FOR FOREMAN AND FIGARO ###
  if prefer :local_env_file, 'figaro'
    copy_file destination_root + '/config/application.yml', destination_root + '/config/application.example.yml'
  elsif prefer :local_env_file, 'foreman'
    copy_file destination_root + '/.env', destination_root + '/.env.example'
  end
  ### DATABASE SEED ###
  if (prefer :authentication, 'devise') and (rails_4_1?)
    copy_from_repo 'db/seeds.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise/master/'
    unless prefer :authorization, 'pundit'
      copy_from_repo 'app/services/create_admin_service.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise/master/'
    end
  end
  if prefer :authorization, 'pundit'
    copy_from_repo 'app/services/create_admin_service.rb', :repo => 'https://raw.github.com/RailsApps/rails-devise-pundit/master/'
  end
  if prefer :local_env_file, 'figaro'
    append_file 'db/seeds.rb' do <<-FILE
# Environment variables (ENV['...']) can be set in the file config/application.yml.
# See http://railsapps.github.io/rails-environment-variables.html
FILE
    end
  elsif prefer :local_env_file, 'foreman'
    append_file 'db/seeds.rb' do <<-FILE
# Environment variables (ENV['...']) can be set in the file .env file.
FILE
    end
  end
  if (prefer :authorization, 'cancan')
    unless prefer :orm, 'mongoid'
      append_file 'db/seeds.rb' do <<-FILE
puts 'ROLES'
YAML.load(ENV['ROLES']).each do |role|
  Role.find_or_create_by_name({ :name => role }, :without_protection => true)
  puts 'role: ' << role
end
FILE
      end
      ## Fix db seed for Rails 4.0
      gsub_file 'db/seeds.rb', /{ :name => role }, :without_protection => true/, 'role' if rails_4?
    else
      append_file 'db/seeds.rb' do <<-FILE
puts 'ROLES'
YAML.load(ENV['ROLES']).each do |role|
  Role.mongo_session['roles'].insert({ :name => role })
  puts 'role: ' << role
end
FILE
      end
    end
  end
  
    append_file 'db/seeds.rb' do <<-FILE
puts 'DEFAULT USERS'
user = User.find_or_create_by_email :name => ENV['ADMIN_NAME'].dup, :email => ENV['ADMIN_EMAIL'].dup, :password => ENV['ADMIN_PASSWORD'].dup, :password_confirmation => ENV['ADMIN_PASSWORD'].dup
puts 'user: ' << user.name
FILE
    end
    # Mongoid doesn't have a 'find_or_create_by' method
    gsub_file 'db/seeds.rb', /find_or_create_by_email/, 'create!' if prefer :orm, 'mongoid'
  end
  ## DEVISE-CONFIRMABLE
  if (prefer :devise_modules, 'confirmable') || (prefer :devise_modules, 'invitable')
    inject_into_file 'app/services/create_admin_service.rb', "        user.confirm!\n", :after => "user.password_confirmation = Rails.application.secrets.admin_password\n"
  end
  ## DEVISE-INVITABLE
  if prefer :devise_modules, 'invitable'
    if prefer :local_env_file, 'foreman'
      run 'foreman run bundle exec rake db:migrate'
    else
      run 'bundle exec rake db:migrate'
    end
    generate 'devise_invitable user'
  end
  ### APPLY DATABASE SEED ###
  unless prefer :orm, 'mongoid'
    unless prefer :database, 'default'
      ## ACTIVE_RECORD
      say_wizard "applying migrations and seeding the database"
      if prefer :local_env_file, 'foreman'
        run 'foreman run bundle exec rake db:migrate'
      else
        run 'bundle exec rake db:migrate'
      end
    end
  else
    ## MONGOID
    say_wizard "dropping database, creating indexes and seeding the database"
    if prefer :local_env_file, 'foreman'
      run 'foreman run bundle exec rake db:drop'
      run 'foreman run bundle exec rake db:mongoid:create_indexes'
    else
      run 'bundle exec rake db:drop'
      run 'bundle exec rake db:mongoid:create_indexes'
    end
  end
  unless prefs[:skip_seeds]
    unless prefer :railsapps, 'rails-recurly-subscription-saas'
      if prefer :local_env_file, 'foreman'
        run 'foreman run bundle exec rake db:seed'
      else
        run 'bundle exec rake db:seed'
      end
    end
  end
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: set up database"' if prefer :git, true
  ### FRONTEND (must run after database migrations) ###
  # generate Devise views with appropriate styling
  if prefer :authentication, 'devise'
    case prefs[:frontend]
      when 'bootstrap3'
        generate 'layout:devise bootstrap3 -f'
      when 'foundation5'
        generate 'layout:devise foundation5 -f'
    end
  end
  # create navigation links using the rails_layout gem
  generate 'layout:navigation -f'
  # replace with specialized navigation partials
  copy_from_repo 'app/views/layouts/_navigation-subdomains_app.html.erb', :prefs => 'subdomains_app'
  ### GIT ###
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: navigation links"' if prefer :git, true
end # after_everything
# >----------------------------- recipes/init.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >---------------------------------[ apps4 ]---------------------------------<
@current_recipe = "apps4"
@before_configs["apps4"].call if @before_configs["apps4"]
say_recipe 'apps4'
@configs[@current_recipe] = config
# >---------------------------- recipes/apps4.rb -----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/apps4.rb

### LEARN-RAILS ####


# >---------------------------- recipes/apps4.rb -----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >-------------------------------[ prelaunch ]-------------------------------<
@current_recipe = "prelaunch"
@before_configs["prelaunch"].call if @before_configs["prelaunch"]
say_recipe 'prelaunch'
@configs[@current_recipe] = config
# >-------------------------- recipes/prelaunch.rb ---------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/prelaunch.rb

if prefer :railsapps, 'rails-prelaunch-signup'

  after_everything do
    say_wizard "recipe running after 'bundle install'"
    repo = 'https://raw.github.com/RailsApps/rails-prelaunch-signup/master/'

    # >-------------------------------[ Clean up starter app ]--------------------------------<

    %w{
      public/index.html
      app/assets/images/rails.png
    }.each { |file| remove_file file }
    # remove commented lines and multiple blank lines from Gemfile
    # thanks to https://github.com/perfectline/template-bucket/blob/master/cleanup.rb
    gsub_file 'Gemfile', /#.*\n/, "\n"
    gsub_file 'Gemfile', /\n^\s*\n/, "\n"
    # remove commented lines and multiple blank lines from config/routes.rb
    gsub_file 'config/routes.rb', /  #.*\n/, "\n"
    gsub_file 'config/routes.rb', /\n^\s*\n/, "\n"
    # GIT
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: clean up starter app"' if prefer :git, true

    # >-------------------------------[ Create a git branch ]--------------------------------<
    if prefer :git, true
      if prefer :prelaunch_branch, 'master'
        unless prefer :main_branch, 'none'
          say_wizard "renaming git branch 'master' to '#{prefs[:main_branch]}' for starter app"
          git :branch => "-m master #{prefs[:main_branch]}"
          git :checkout => "-b master"
        else
          say_wizard "creating prelaunch app on git branch 'master'"
        end
      else
        say_wizard "creating new git branch '#{prefs[:prelaunch_branch]}' for prelaunch app"
        git :checkout => "-b #{prefs[:prelaunch_branch]}"
      end
    end

    # >-------------------------------[ Models ]--------------------------------<

    copy_from_repo 'app/models/user.rb', :repo => repo

    # >-------------------------------[ Init ]--------------------------------<
    copy_from_repo 'config/application.yml', :repo => repo
    remove_file 'config/application.example.yml'
    copy_file destination_root + '/config/application.yml', destination_root + '/config/application.example.yml'
    copy_from_repo 'db/seeds.rb', :repo => repo
    run 'bundle exec rake db:seed'

    # >-------------------------------[ Controllers ]--------------------------------<

    copy_from_repo 'app/controllers/confirmations_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/home_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/registrations_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/users_controller.rb', :repo => repo

    # >-------------------------------[ Mailers ]--------------------------------<

    generate 'mailer UserMailer'
    copy_from_repo 'spec/mailers/user_mailer_spec.rb', :repo => repo
    copy_from_repo 'app/mailers/user_mailer.rb', :repo => repo

    # >-------------------------------[ Views ]--------------------------------<

    copy_from_repo 'app/views/devise/confirmations/show.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/mailer/confirmation_instructions.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/_thankyou.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/new.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/shared/_links.html.erb', :repo => repo
    copy_from_repo 'app/views/home/index.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/welcome_email.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/welcome_email.text.erb', :repo => repo
    copy_from_repo 'app/views/users/index.html.erb', :repo => repo
    copy_from_repo 'public/thankyou.html', :repo => repo

    # >-------------------------------[ Routes ]--------------------------------<

    copy_from_repo 'config/routes.rb', :repo => repo
    ### CORRECT APPLICATION NAME ###
    gsub_file 'config/routes.rb', /^.*.routes.draw do/, "#{app_const}.routes.draw do"

    # >-------------------------------[ Assets ]--------------------------------<

    copy_from_repo 'app/assets/javascripts/application.js', :repo => repo
    copy_from_repo 'app/assets/stylesheets/application.css.scss', :repo => repo

    # >-------------------------------[ Cucumber ]--------------------------------<
    say_wizard "copying Cucumber scenarios from the rails-prelaunch-signup examples"
    copy_from_repo 'features/admin/send_invitations.feature', :repo => repo
    copy_from_repo 'features/admin/view_progress.feature', :repo => repo
    copy_from_repo 'features/visitors/request_invitation.feature', :repo => repo
    copy_from_repo 'features/users/sign_in.feature', :repo => repo
    copy_from_repo 'features/users/sign_up.feature', :repo => repo
    copy_from_repo 'features/users/user_show.feature', :repo => repo
    copy_from_repo 'features/step_definitions/admin_steps.rb', :repo => repo
    copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
    copy_from_repo 'features/step_definitions/visitor_steps.rb', :repo => repo
    copy_from_repo 'config/locales/devise.en.yml', :repo => repo

    ### GIT ###
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: prelaunch app"' if prefer :git, true
  end # after_bundler
end # rails-prelaunch-signup
# >-------------------------- recipes/prelaunch.rb ---------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >-------------------------------[ prelaunch ]-------------------------------<
@current_recipe = "saas"
@before_configs["saas"].call if @before_configs["saas"]
say_recipe 'prelaunch'
@configs[@current_recipe] = config
# >-------------------------- recipes/prelaunch.rb ---------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/saas.rb

if prefer :railsapps, 'rails-stripe-membership-saas'

  after_everything do
    say_wizard "recipe running after 'bundle install'"
    repo = 'https://raw.github.com/RailsApps/rails-stripe-membership-saas/master/'

    # >-------------------------------[ Clean up starter app ]--------------------------------<

    %w{
      public/index.html
      app/assets/images/rails.png
    }.each { |file| remove_file file }
    # remove commented lines and multiple blank lines from Gemfile
    # thanks to https://github.com/perfectline/template-bucket/blob/master/cleanup.rb
    gsub_file 'Gemfile', /#.*\n/, "\n"
    gsub_file 'Gemfile', /\n^\s*\n/, "\n"
    # remove commented lines and multiple blank lines from config/routes.rb
    gsub_file 'config/routes.rb', /  #.*\n/, "\n"
    gsub_file 'config/routes.rb', /\n^\s*\n/, "\n"
    # GIT
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: clean up starter app"' if prefer :git, true

    # >-------------------------------[ Migrations ]--------------------------------<
    generate 'migration AddStripeToUsers customer_id:string last_4_digits:string'
    run 'bundle exec rake db:drop'
    run 'bundle exec rake db:migrate'

    # >-------------------------------[ Models ]--------------------------------<
    copy_from_repo 'app/models/ability.rb', :repo => repo
    copy_from_repo 'app/models/user.rb', :repo => repo

    # >-------------------------------[ Init ]--------------------------------<
    copy_from_repo 'config/application.yml', :repo => repo
    remove_file 'config/application.example.yml'
    copy_file destination_root + '/config/application.yml', destination_root + '/config/application.example.yml'
    copy_from_repo 'db/seeds.rb', :repo => repo
    copy_from_repo 'config/initializers/stripe.rb', :repo => repo
    run 'bundle exec rake db:seed'

    # >-------------------------------[ Controllers ]--------------------------------<
    copy_from_repo 'app/controllers/home_controller.rb', :repo => repo
    generate 'controller content silver gold platinum --skip-assets --skip-helper'
    copy_from_repo 'app/controllers/content_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/registrations_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/application_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/users_controller.rb', :repo => repo

    # >-------------------------------[ Mailers ]--------------------------------<
    generate 'mailer UserMailer'
    copy_from_repo 'app/mailers/user_mailer.rb', :repo => repo

    # >-------------------------------[ Views ]--------------------------------<
    copy_from_repo 'app/views/home/index.html.erb', :repo => repo
    copy_from_repo 'app/views/layouts/_navigation.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/new.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/edit.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/expire_email.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/expire_email.text.erb', :repo => repo

    # >-------------------------------[ Routes ]--------------------------------<
    copy_from_repo 'config/routes.rb', :repo => repo
    ### CORRECT APPLICATION NAME ###
    gsub_file 'config/routes.rb', /^.*.routes.draw do/, "#{app_const}.routes.draw do"

    # >-------------------------------[ Assets ]--------------------------------<
    copy_from_repo 'app/assets/javascripts/application.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/jquery.readyselector.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/jquery.externalscript.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/registrations.js', :repo => repo
    copy_from_repo 'app/assets/stylesheets/application.css.scss', :repo => repo
    copy_from_repo 'app/assets/stylesheets/pricing.css.scss', :repo => repo

    # >-------------------------------[ RSpec ]--------------------------------<
    say_wizard "copying RSpec tests from the rails-stripe-membership-saas examples"
    copy_from_repo 'spec/factories/roles.rb', :repo => repo
    copy_from_repo 'spec/models/user_spec.rb', :repo => repo
    copy_from_repo 'spec/controllers/content_controller_spec.rb', :repo => repo
    copy_from_repo 'spec/mailers/user_mailer_spec.rb', :repo => repo
    copy_from_repo 'spec/stripe/stripe_config_spec.rb', :repo => repo
    copy_from_repo 'spec/support/stripe_helper.rb', :repo => repo
    copy_from_repo 'spec/support/fixtures/success.json', :repo => repo

    # >-------------------------------[ Cucumber ]--------------------------------<
    say_wizard "copying Cucumber scenarios from the rails-stripe-membership-saas examples"
    remove_file 'features/users/user_show.feature'
    copy_from_repo 'features/support/paths.rb', :repo => repo
    copy_from_repo 'features/users/sign_in.feature', :repo => repo
    copy_from_repo 'features/users/sign_up.feature', :repo => repo
    copy_from_repo 'features/users/sign_up_with_stripe.feature', :repo => repo
    copy_from_repo 'features/users/user_edit.feature', :repo => repo
    copy_from_repo 'features/users/user_delete.feature', :repo => repo
    copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
    copy_from_repo 'features/step_definitions/form_helper_steps.rb', :repo => repo
    copy_from_repo 'config/locales/devise.en.yml', :repo => repo

    ### GIT ###
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: membership app"' if prefer :git, true
  end # after_bundler
end # rails-stripe-membership-saas

if prefer :railsapps, 'rails-recurly-subscription-saas'

  after_everything do
    say_wizard "recipe running after 'bundle install'"
    repo = 'https://raw.github.com/RailsApps/rails-recurly-subscription-saas/master/'

    # >-------------------------------[ Clean up starter app ]--------------------------------<

    %w{
      public/index.html
      app/assets/images/rails.png
    }.each { |file| remove_file file }
    # remove commented lines and multiple blank lines from Gemfile
    # thanks to https://github.com/perfectline/template-bucket/blob/master/cleanup.rb
    gsub_file 'Gemfile', /#.*\n/, "\n"
    gsub_file 'Gemfile', /\n^\s*\n/, "\n"
    # remove commented lines and multiple blank lines from config/routes.rb
    gsub_file 'config/routes.rb', /  #.*\n/, "\n"
    gsub_file 'config/routes.rb', /\n^\s*\n/, "\n"
    # GIT
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: clean up starter app"' if prefer :git, true

    # >-------------------------------[ Migrations ]--------------------------------<
    generate 'migration AddRecurlyToUsers first_name:string last_name:string customer_id:string'
    run 'bundle exec rake db:drop'
    run 'bundle exec rake db:migrate'

    # >-------------------------------[ Models ]--------------------------------<
    copy_from_repo 'app/models/ability.rb', :repo => repo
    copy_from_repo 'app/models/user.rb', :repo => repo

    # >-------------------------------[ Init ]--------------------------------<
    copy_from_repo 'config/application.yml', :repo => repo
    remove_file 'config/application.example.yml'
    copy_file destination_root + '/config/application.yml', destination_root + '/config/application.example.yml'
    copy_from_repo 'db/seeds.rb', :repo => repo
    copy_from_repo 'config/initializers/recurly.rb', :repo => repo
    run 'bundle exec rake db:seed'

    # >-------------------------------[ Controllers ]--------------------------------<
    copy_from_repo 'app/controllers/home_controller.rb', :repo => repo
    generate 'controller content silver gold platinum --skip-assets --skip-helper'
    copy_from_repo 'app/controllers/content_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/registrations_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/application_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/users_controller.rb', :repo => repo
    copy_from_repo 'app/controllers/recurly_controller.rb', :repo => repo

    # >-------------------------------[ Mailers ]--------------------------------<
    generate 'mailer UserMailer'
    copy_from_repo 'app/mailers/user_mailer.rb', :repo => repo

    # >-------------------------------[ Views ]--------------------------------<
    copy_from_repo 'app/views/home/index.html.erb', :repo => repo
    copy_from_repo 'app/views/layouts/_navigation.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/new.html.erb', :repo => repo
    copy_from_repo 'app/views/devise/registrations/edit.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/expire_email.html.erb', :repo => repo
    copy_from_repo 'app/views/user_mailer/expire_email.text.erb', :repo => repo

    # >-------------------------------[ Routes ]--------------------------------<
    copy_from_repo 'config/routes.rb', :repo => repo
    ### CORRECT APPLICATION NAME ###
    gsub_file 'config/routes.rb', /^.*.routes.draw do/, "#{app_const}.routes.draw do"

    # >-------------------------------[ Assets ]--------------------------------<
    copy_from_repo 'app/assets/javascripts/application.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/jquery.readyselector.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/recurly.js', :repo => repo
    copy_from_repo 'app/assets/javascripts/registrations.js', :repo => repo
    copy_from_repo 'app/assets/stylesheets/application.css.scss', :repo => repo
    copy_from_repo 'app/assets/stylesheets/pricing.css.scss', :repo => repo

    # >-------------------------------[ RSpec ]--------------------------------<
    say_wizard "copying RSpec tests from the rails-recurly-subscription-saas examples"
    copy_from_repo 'spec/factories/roles.rb', :repo => repo
    copy_from_repo 'spec/factories/users.rb', :repo => repo
    copy_from_repo 'spec/models/user_spec.rb', :repo => repo
    copy_from_repo 'spec/controllers/content_controller_spec.rb', :repo => repo
    copy_from_repo 'spec/mailers/user_mailer_spec.rb', :repo => repo
    copy_from_repo 'spec/recurly/recurly_config_spec.rb', :repo => repo

    # >-------------------------------[ Cucumber ]--------------------------------<
    say_wizard "copying Cucumber scenarios from the rails-recurly-subscription-saas examples"
    remove_file 'features/users/user_show.feature'
    copy_from_repo 'features/support/paths.rb', :repo => repo
    copy_from_repo 'features/users/sign_in.feature', :repo => repo
    copy_from_repo 'features/users/sign_up.feature', :repo => repo
    copy_from_repo 'features/users/sign_up_with_recurly.feature', :repo => repo
    copy_from_repo 'features/users/user_edit.feature', :repo => repo
    copy_from_repo 'features/users/user_delete.feature', :repo => repo
    copy_from_repo 'features/step_definitions/user_steps.rb', :repo => repo
    copy_from_repo 'features/step_definitions/form_helper_steps.rb', :repo => repo
    copy_from_repo 'config/locales/devise.en.yml', :repo => repo

    ### GIT ###
    git :add => '-A' if prefer :git, true
    git :commit => '-qm "rails_apps_composer: membership app"' if prefer :git, true
  end # after_bundler
end # rails-recurly-subscription-saas
# >-------------------------- recipes/prelaunch.rb ---------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >--------------------------------[ extras ]---------------------------------<
@current_recipe = "extras"
@before_configs["extras"].call if @before_configs["extras"]
say_recipe 'extras'
config = {}
config['ban_spiders'] = yes_wizard?("Set a robots.txt file to ban spiders?") if true && true unless config.key?('ban_spiders') || prefs.has_key?(:ban_spiders)
config['github'] = yes_wizard?("Create a GitHub repository?") if true && true unless config.key?('github') || prefs.has_key?(:github)
config['local_env_file'] = multiple_choice("Add gem and file for environment variables?", [["None", "none"], ["Add .env with Foreman", "foreman"], ["Add application.yml with Figaro", "figaro"]]) if true && true unless config.key?('local_env_file') || prefs.has_key?(:local_env_file)
config['quiet_assets'] = yes_wizard?("Reduce assets logger noise during development?") if true && true unless config.key?('quiet_assets') || prefs.has_key?(:quiet_assets)
config['better_errors'] = yes_wizard?("Improve error reporting with 'better_errors' during development?") if true && true unless config.key?('better_errors') || prefs.has_key?(:better_errors)
config['pry'] = yes_wizard?("Use 'pry' as console replacement during development and test?") if true && true unless config.key?('pry') || prefs.has_key?(:pry)
@configs[@current_recipe] = config
# >---------------------------- recipes/extras.rb ----------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/extras.rb

## RVMRC
rvmrc_detected = false
if File.exist?('.ruby-gemset')
  rvmrc_file = File.read('.ruby-gemset')
  rvmrc_detected = rvmrc_file.include? app_name
end
unless rvmrc_detected || (prefs.has_key? :rvmrc)
  prefs[:rvmrc] = yes_wizard? "Use or create a project-specific rvm gemset?"
end
if prefs[:rvmrc]
  if which("rvm")
    say_wizard "recipe creating project-specific rvm gemset and .rvmrc"
    # using the rvm Ruby API, see:
    # http://blog.thefrontiergroup.com.au/2010/12/a-brief-introduction-to-the-rvm-ruby-api/
    # https://rvm.io/integration/passenger
    if ENV['MY_RUBY_HOME'] && ENV['MY_RUBY_HOME'].include?('rvm')
      begin
        gems_path = ENV['MY_RUBY_HOME'].split(/@/)[0].sub(/rubies/,'gems')
        ENV['GEM_PATH'] = "#{gems_path}:#{gems_path}@global"
        require 'rvm'
        RVM.use_from_path! File.dirname(File.dirname(__FILE__))
      rescue LoadError
        raise "RVM gem is currently unavailable."
      end
    end
    say_wizard "creating RVM gemset '#{app_name}'"
    RVM.gemset_create app_name
    say_wizard "switching to gemset '#{app_name}'"
    # RVM.gemset_use! requires rvm version 1.11.3.5 or newer
    rvm_spec =
      if Gem::Specification.respond_to?(:find_by_name)
        Gem::Specification.find_by_name("rvm")
      else
        Gem.source_index.find_name("rvm").last
      end
      unless rvm_spec.version > Gem::Version.create('1.11.3.4')
        say_wizard "rvm gem version: #{rvm_spec.version}"
        raise "Please update rvm gem to 1.11.3.5 or newer"
      end
    begin
      RVM.gemset_use! app_name
    rescue => e
      say_wizard "rvm failure: unable to use gemset #{app_name}, reason: #{e}"
      raise
    end
    run "rvm gemset list"
    if File.exist?('.ruby-version')
      say_wizard ".ruby-version file already exists"
    else
      create_file '.ruby-version', "#{RUBY_VERSION}\n"
    end
    if File.exist?('.ruby-gemset')
      say_wizard ".ruby-gemset file already exists"
    else
      create_file '.ruby-gemset', "#{app_name}\n"
    end
  else
    say_wizard "WARNING! RVM does not appear to be available."
  end
end

## QUIET ASSETS
if config['quiet_assets']
  prefs[:quiet_assets] = true
end
if prefs[:quiet_assets]
  say_wizard "recipe setting quiet_assets for reduced asset pipeline logging"
  add_gem 'quiet_assets', :group => :development
end

## LOCAL_ENV.YML FILE
if config['local_env_file']
  case config['local_env_file']
  when 'figaro'
    prefs[:local_env_file] = 'figaro'
  when 'foreman'
    prefs[:local_env_file] = 'foreman'
  end
end
if prefer :local_env_file, 'figaro'
  say_wizard "recipe creating application.yml file for environment variables with figaro"
  if rails_4_1?
    add_gem 'figaro', :github => 'laserlemon/figaro'
  else
    add_gem 'figaro'
  end
elsif prefer :local_env_file, 'foreman'
  say_wizard "recipe creating .env file for development environment variables with foreman"
  add_gem 'foreman', :group => :development
end

## BETTER ERRORS
if config['better_errors']
  prefs[:better_errors] = true
end
if prefs[:better_errors]
  say_wizard "recipe adding better_errors gem"
  add_gem 'better_errors', :group => :development
  if RUBY_ENGINE == 'ruby'
    add_gem 'binding_of_caller', :group => :development, :platforms => [:mri_21]
  end
end

# Pry
if config['pry']
  prefs[:pry] = true
end
if prefs[:pry]
  say_wizard "recipe adding pry-rails gem"
  add_gem 'pry-rails', :group => [:development, :test]
  add_gem 'pry-rescue', :group => [:development, :test]
end

## BAN SPIDERS
if config['ban_spiders']
  prefs[:ban_spiders] = true
end
if prefs[:ban_spiders]
  say_wizard "recipe banning spiders by modifying 'public/robots.txt'"
  after_bundler do
    gsub_file 'public/robots.txt', /# User-Agent/, 'User-Agent'
    gsub_file 'public/robots.txt', /# Disallow/, 'Disallow'
  end
end

## JSRUNTIME
case RbConfig::CONFIG['host_os']
  when /linux/i
    prefs[:jsruntime] = yes_wizard? "Add 'therubyracer' JavaScript runtime (for Linux users without node.js)?" unless prefs.has_key? :jsruntime
    if prefs[:jsruntime]
      say_wizard "recipe adding 'therubyracer' JavaScript runtime gem"
      add_gem 'therubyracer', :platform => :ruby
    end
end

## AFTER_EVERYTHING
after_everything do
  say_wizard "recipe removing unnecessary files and whitespace"
  %w{
    public/index.html
    app/assets/images/rails.png
  }.each { |file| remove_file file }
  # remove temporary Haml gems from Gemfile when Slim is selected
  if prefer :templates, 'slim'
    gsub_file 'Gemfile', /  gem 'haml2slim'\n/, "\n"
    gsub_file 'Gemfile', /  gem 'html2haml'\n/, "\n"
  end
  # remove commented lines and multiple blank lines from Gemfile
  # thanks to https://github.com/perfectline/template-bucket/blob/master/cleanup.rb
  gsub_file 'Gemfile', /#.*\n/, "\n"
  gsub_file 'Gemfile', /\n^\s*\n/, "\n"
  # remove commented lines and multiple blank lines from config/routes.rb
  gsub_file 'config/routes.rb', /  #.*\n/, "\n"
  gsub_file 'config/routes.rb', /\n^\s*\n/, "\n"
  # GIT
  git :add => '-A' if prefer :git, true
  git :commit => '-qm "rails_apps_composer: extras"' if prefer :git, true
end

## GITHUB
if config['github']
  prefs[:github] = true
end
if prefs[:github]
  add_gem 'hub', :require => nil, :group => [:development]
  after_everything do
    say_wizard "recipe creating GitHub repository"
    git_uri = `git config remote.origin.url`.strip
    unless git_uri.size == 0
      say_wizard "Repository already exists:"
      say_wizard "#{git_uri}"
    else
      run "hub create #{app_name}"
      unless prefer :railsapps, 'rails-prelaunch-signup'
        run "hub push -u origin master"
      else
        run "hub push -u origin #{prefs[:prelaunch_branch]}"
        run "hub push -u origin #{prefs[:main_branch]}" unless prefer :main_branch, 'none'
      end
    end
  end
end
# >---------------------------- recipes/extras.rb ----------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<

# >-------------------------- templates/recipe.erb ---------------------------start<
# >------------------------------[ deployment ]-------------------------------<
@current_recipe = "deployment"
@before_configs["deployment"].call if @before_configs["deployment"]
say_recipe 'deployment'
config = {}
config['deployment'] = multiple_choice("Add a deployment mechanism?", [["None", "none"], ["Capistrano3", "capistrano3"]]) if true && true unless config.key?('deployment') || prefs.has_key?(:deployment)
@configs[@current_recipe] = config
# >-------------------------- recipes/deployment.rb --------------------------start<

# Application template recipe for the rails_apps_composer. Change the recipe here:
# https://github.com/RailsApps/rails_apps_composer/blob/master/recipes/deployment.rb

case config['deployment']
when 'capistrano3'
  prefs[:deployment] = 'capistrano3'
end

if prefer :deployment, 'capistrano3'
  say_wizard "recipe adding capistrano gems"
  add_gem 'capistrano', '~> 3.0.1', group: :development
  add_gem 'capistrano-rvm', '~> 0.1.1', group: :development
  add_gem 'capistrano-bundler', group: :development
  add_gem 'capistrano-rails', '~> 1.1.0', group: :development
  add_gem 'capistrano-rails-console', group: :development
  after_bundler do
    say_wizard 'recipe capistrano file'
    run 'bundle exec cap install'
  end
end
# >-------------------------- recipes/deployment.rb --------------------------end<
# >-------------------------- templates/recipe.erb ---------------------------end<


# >-----------------------------[ Final Gemfile Write ]------------------------------<
Gemfile.write

# >---------------------------------[ Diagnostics ]----------------------------------<

# remove prefs which are diagnostically irrelevant
redacted_prefs = prefs.clone
redacted_prefs.delete(:ban_spiders)
redacted_prefs.delete(:better_errors)
redacted_prefs.delete(:pry)
redacted_prefs.delete(:dev_webserver)
redacted_prefs.delete(:git)
redacted_prefs.delete(:github)
redacted_prefs.delete(:jsruntime)
redacted_prefs.delete(:local_env_file)
redacted_prefs.delete(:main_branch)
redacted_prefs.delete(:prelaunch_branch)
redacted_prefs.delete(:prod_webserver)
redacted_prefs.delete(:quiet_assets)
redacted_prefs.delete(:rvmrc)
redacted_prefs.delete(:templates)


@current_recipe = nil

# >-----------------------------[ Run 'Bundle Install' ]-------------------------------<

say_wizard "Installing gems. This will take a while."
run 'bundle install --without production'
say_wizard "Updating gem paths."
Gem.clear_paths
# >-----------------------------[ Run 'After Bundler' Callbacks ]-------------------------------<

say_wizard "Running 'after bundler' callbacks."
if prefer :templates, 'haml'
  say_wizard "importing html2haml conversion tool"
  require 'html2haml'
end
if prefer :templates, 'slim'
say_wizard "importing html2haml and haml2slim conversion tools"
  require 'html2haml'
  require 'haml2slim'
end
@after_blocks.each{|b| config = @configs[b[0]] || {}; @current_recipe = b[0]; puts @current_recipe; b[1].call}

# >-----------------------------[ Run 'After Everything' Callbacks ]-------------------------------<

@current_recipe = nil
say_wizard "Running 'after everything' callbacks."
@after_everything_blocks.each{|b| config = @configs[b[0]] || {}; @current_recipe = b[0]; puts @current_recipe; b[1].call}

@current_recipe = nil
say_wizard("Your new application will contain diagnostics in its README file.")
say_wizard("When reporting an issue on GitHub, include the README diagnostics.")
say_wizard "Finished running the rails_apps_composer app template."
say_wizard "Your new Rails app is ready. Time to run 'bundle install'."
=end
