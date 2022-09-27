**Skybox Firewall Assurance : Check daily for shadow rules**

Checks all new rules implemented to determine if the rules are shadowed, and can therefore be removed

This can be run for the previous day, or for several days before. 
It would be recommended to rather run the script daily, as the script could take an enormous amount of time to complete, depending 
on the size of your enviornment.

A suggestion would be to use an orchestrator, or to run another script, which can format this output to run against your firewalls.

**Note, use a ticketing system to audit your changes**