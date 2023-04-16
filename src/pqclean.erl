%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2023, Andrew Bennett
%%% @doc See {@link pqclean_nif}
%%%
%%% @end
%%% Created :  15 April 2023 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(pqclean).
-compile(warn_missing_spec).
-author("potatosaladx@gmail.com").

%% Internal API
-export([
    priv_dir/0
]).

%%%=============================================================================
%%% Internal API functions
%%%=============================================================================

%% @private
-spec priv_dir() -> file:filename_all().
priv_dir() ->
    case code:priv_dir(pqclean) of
        {error, bad_name} ->
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    filename:join([filename:dirname(Filename), "../priv"]);
                _ ->
                    "../priv"
            end;
        Dir ->
            Dir
    end.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
