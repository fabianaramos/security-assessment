Rails.application.routes.draw do
  root "assessments#index"
  resources :assessments, only: %i[index new create show destroy]

  get "up" => "rails/health#show", as: :rails_health_check
end
