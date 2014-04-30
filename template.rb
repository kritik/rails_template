

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


