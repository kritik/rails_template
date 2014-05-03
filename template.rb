

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
gem 'bcrypt-ruby'
# gem 'airbrake'
gem 'whenever', :require => false
gem 'therubyracer', :require => 'v8'
gem 'paper_trail', '~> 3.0.1'
gem 'validates_existence', :git => 'https://github.com/perfectline/validates_existence.git'

initializer 'bigdecimal.rb', <<-CODE
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
gem 'sinatra', :require => nil
gem 'sidekiq'
gem 'sidekiq-failures'

route "mount Sidekiq::Web => '/sidekiq'"
route "require 'sidekiq/web'"
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





# >-----------------------------[ Run Bundler ]-------------------------------<

say_wizard "Running Bundler install. This will take a while."
run 'bundle install'



rakefile("db.rake") do
  <<-TASK
namespace :db do

  task :recreate => :environment do
    Rake::Task["db:drop"].execute
    Rake::Task["db:create"].execute
    Rake::Task["db:migrate"].execute
    Rake::Task["db:seed"].execute
  end

end
  TASK
end


# >-----------------------------[ Create Users ]-------------------------------<

generate(:model, "user", "email:string:uniq", "first_name:string", "last_name:string", "encrypted_password:string", "time_zone_name:string")
generate(:model, "account", "user:references")
generate("paper_trail:install")

file 'app/models/account.rb', <<-CODE
# Mainly it is a company which can have several shops and one user, who is the owner
class Account < ActiveRecord::Base
  belongs_to :user

  validates :user_id, presence: true, existence: true

end
CODE
file 'app/models/user.rb', <<-CODE
require 'bcrypt'
class User < ActiveRecord::Base
  has_paper_trail
  has_many :accounts, dependent: :destroy
  
  attr_reader :password
   
  validates :email, presence: true, length: {maximum: 255}, uniqueness: {case_sensitive: false}
  validates :password,
    confirmation: true,
    length: { minimum: 3 }, on: :update, if: :password_required?
    
  before_validation do
    self.email      = self.email.downcase       if self.email.present?
    self.first_name = self.first_name.titleize  if self.first_name.present?
    self.last_name  = self.last_name.titleize   if self.last_name.present?
  end
  
  def name
    "#\{first_name} #\{last_name}".strip
  end
  
  def password_required?
    password.present?
  end
  
  
  def self.authenticate(params)
    user = find_by(email: params[:email])

    if user && user.valid_password?(params[:password])
      return user
    end
  end
  
  def valid_password?(string)
    BCrypt::Password.new(string) == self.encrypted_password
  end
  
  def password= str
    @password = str
    self.encrypted_password = BCrypt::Password.create(str)
  end
end
CODE

# >------------------------[ Capistrano And Others ]----------------------------<
gem_group :development do
  gem 'annotate'
  gem 'active_record_query_trace'
  gem 'pry-rails'
  gem 'capistrano'
  gem 'capistrano-rails'
  gem 'capistrano-bundler'
  gem 'sepastian-capistrano3-unicorn', require: false
  gem 'capistrano-sidekiq'
end
initializer 'active_record_query_trace.rb', <<-CODE
# Using to find out who run SQL query
ActiveRecordQueryTrace.enabled = false

# Default is 5. Setting to 0 includes entire trace.
# ActiveRecordQueryTrace.lines = 10
CODE

file 'config/deploy.rb', <<-CODE
lock '3.2.1'

set :application, '#{app_name}'
set :repo_url,    'git@code.perfectline.co:perfectline/#{app_name}.git'


set :scm, :git
set :format, :pretty
set :log_level, :debug
set :sidekiq_options, "-C #\{fetch(:deploy_to)}/config/sidekiq.yml"
set :linked_dirs, %w{bin log tmp/pids tmp/cache tmp/sockets vendor/bundle public/assets public/system public/uploads}

SSHKit.config.command_map[:rake]  = "bundle exec rake"
SSHKit.config.command_map[:rails] = "bundle exec rails"

set :keep_releases, 5


namespace :deploy do
  after :restart,  'unicorn:restart'
end
CODE

file 'config/deploy/production.rb', <<-CODE
# Simple Role Syntax
# ==================
# Supports bulk-adding hosts to roles, the primary
# server in each group is considered to be the first
# unless any hosts have the primary property set.
# Don't declare `role :all`, it's a meta role
role :app, %w{deploy@example.com}
role :web, %w{deploy@example.com}
role :db,  %w{deploy@example.com}

# Extended Server Syntax
# ======================
# This can be used to drop a more detailed server
# definition into the server list. The second argument
# something that quacks like a hash can be used to set
# extended properties on the server.
server 'example.com', user: 'deploy', roles: %w{web app}, my_property: :my_value

# you can set custom ssh options
# it's possible to pass any option but you need to keep in mind that net/ssh understand limited list of options
# you can see them in [net/ssh documentation](http://net-ssh.github.io/net-ssh/classes/Net/SSH.html#method-c-start)
# set it globally
#  set :ssh_options, {
#    keys: %w(/home/rlisowski/.ssh/id_rsa),
#    forward_agent: false,
#    auth_methods: %w(password)
#  }
# and/or per server
# server 'example.com',
#   user: 'user_name',
#   roles: %w{web app},
#   ssh_options: {
#     user: 'user_name', # overrides user setting above
#     keys: %w(/home/user_name/.ssh/id_rsa),
#     forward_agent: false,
#     auth_methods: %w(publickey password)
#     # password: 'please use keys'
#   }
# setting per server overrides global ssh_options
CODE
file 'config/deploy/staging.rb', <<-CODE
host = "perfectline-staging.vps.servefinity.com"
role :app, [host]
role :web, [host]
role :db,  [host]


server host, user: 'deploy', roles: %w{web app db}, my_property: :my_value

set :branch,  ENV["REVISION"] || ENV["BRANCH_NAME"] || "master"
set :deploy_to,     "/var/www/#{app_name}"
set :stage,         :staging
set :use_sudo,      false
set :rails_env,        fetch(:stage)
set :unicorn_rack_env, fetch(:stage)
set :sidekiq_options, "-C #\{current_path}/config/sidekiq.yml"
#set :unicorn_pid, Proc.new{ File.join(fetch(:app_path), 'tmp', 'pids', 'unicorn.pid') }
CODE
file 'Capfile', <<-CODE
# Load DSL and Setup Up Stages
require 'capistrano/setup'
require 'capistrano/deploy'

require 'capistrano/console'
require 'capistrano/bundler'
require 'capistrano/rails/assets'
require 'capistrano/rails/migrations'
# require "whenever/capistrano"
require 'capistrano/unicorn'
require 'capistrano/sidekiq'
# require 'airbrake/capistrano3'

# Loads custom tasks from `lib/capistrano/tasks' if you have any defined.
Dir.glob('lib/capistrano/tasks/*.cap').each { |r| import r }
CODE
file 'lib/capistrano/tasks/log.cap', <<-CODE
namespace :logs do
  desc "tail -f server logs."
  task :web do
    on roles(:web) do
      execute "tail -f #\{shared_path}/log/#\{fetch(:stage)}.log"
    end
  end

  desc "tail -f elasticsearch logs."
  task :elastic do
    on roles(:web) do
      execute "tail -f #\{shared_path}/log/elasticsearch.log"
    end
  end
end
CODE
file 'lib/capistrano/tasks/db.cap', <<-CODE
namespace :db do
  def load_db_data
    #Currently read logs from local data
    #data = capture("cat #\{current_path}/config/database.yml")
    data = File.read("config/database.yml")

    yaml = YAML.load(data)[fetch(:stage).to_s]
    set :environment_info,  yaml

    now = Time.now
    backup_time = [now.year,now.month,now.day,now.hour,now.min,now.sec].join
    execute :mkdir, "-p", "#\{shared_path}/db_backups"
    set :backup_file, "#\{shared_path}/db_backups/#\{fetch(:environment_info)['database']}-snapshot-#\{backup_time}.sql"
  end


  desc "Backup your MySQL or PostgreSQL database to shared_path+/db_backups"
  task :dump do
    on roles(:db), only: {primary: true} do
      load_db_data
      @environment_info = fetch(:environment_info)

      host = %{-U #\{@environment_info['username']} -h #\{@environment_info['host']} } if @environment_info['host']
      cmd = %{pg_dump #\{host} -Fc #\{@environment_info['database']} > #\{fetch(:backup_file)}.dump}
      execute cmd do |ch, stream, out |
        ch.send_data "#\{@environment_info['password']}\n" if out.to_s =~ /^Password:/
      end
    end
  end

  desc "Sync your production database to your local workstation"
  task :to_local do
    on roles(:db), only: {primary: true} do
      dump
      filename = "/tmp/#\{application}.dump"
      dev_info = YAML.load_file("config/database.yml")['development']
      download! "#\{fetch(:backup_file)}.dump", filename
      `pg_restore --verbose --clean --no-acl --no-owner -d #\{dev_info['database']} #\{filename}`
    end
  end
end
CODE