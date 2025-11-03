class HomeController < ApplicationController
  def index
    @categories = ToolRegistry.categories
    @tools_by_category = @categories.index_with { |cat| ToolRegistry.by_category(cat) }
  end
end
