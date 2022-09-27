#!/usr/bin/env python3

import csv
from turtle import done
from skybox import skybox
from rich import print
import maskpass

external_api_user = "userside_api"  # user with the skybox "api user" role
externernal_api_password = ""
internal_api_user = input("Enter skybox username: ")  # user with skybox "admin" role
internal_api_password = maskpass.askpass("Enter skybox password: ")
host = "<host url>"
port = "443"


def main():

    sb = skybox(
        host=host,
        port=port,
        external_api_user=external_api_user,
        externernal_api_password=externernal_api_password,
        internal_api_user=internal_api_user,
        internal_api_password=internal_api_password,
    )

    print("Looking for the most recent changes...")

    changes = sb.changes(period=1)
    number_of_changes = changes["size"]

    print(f"We found {number_of_changes} changes")

    list_of_changes = []
    counter = 1
    for change in changes["elements"]:

        print(f"Doing change id {change['id']}: {counter}/{number_of_changes}")
        counter += 1

        change_type = change["type"]
        change_state = change["state"]

        if "systemDescription" in change["metadata"]:
            change_systemDescription = change["metadata"]["systemDescription"]
        else:
            change_systemDescription = None

        if (
            change_type != "com.skybox.view.transfer.fwchanges.FwChangeTypeEnum.OBJECT"
            and change_state
            != "com.skybox.view.transfer.fwchanges.FwChangeStateEnum.DELETED"
            and change_systemDescription != "Major access list change"
        ):

            affected_rule_id = sb.affected_rule_ids_for_change(change=change)

            if affected_rule_id:  # is this a change which didn't have 1000 changes?
                change["affected_rule_id"] = affected_rule_id

                affected_rule_info = sb.access_rule_info(rule_id=affected_rule_id)
                change["affected_rule_info"] = affected_rule_info

                shadowing_rule_ids = sb.shadowing_rule_ids_for_rule_id(rule_id=affected_rule_id)
                change["shadowing_rule_ids"] = shadowing_rule_ids

                if shadowing_rule_ids:

                    shadow_rule_list = []
                    for shadow_id in shadowing_rule_ids:
                        shadow_rule_info = sb.access_rule_info(rule_id=shadow_id)
                        shadow_rule_list.append(shadow_rule_info)

                    change["shadow_rule_info"] = shadow_rule_list

                list_of_changes.append(change)

    # did we find any changes where the rules are shadowed?
    for change in list_of_changes:
        if change["shadowing_rule_ids"]:
            print(change)

    # create csv files for this infor
    ftd_data_file = open("ftd_changes.csv", "w", newline="")
    ftd_csv_writer = csv.writer(ftd_data_file)
    asa_data_file = open("asa_changes.csv", "w", newline="")
    asa_csv_writer = csv.writer(asa_data_file)

    done_ftd_headers = False
    done_asa_headers = False
    for change in list_of_changes:
        if change["shadowing_rule_ids"]:

            if "FIREPOWER" in change["changedEntity"]["hostToolTip"]["osName"].upper():

                if not done_ftd_headers:
                    header = change.keys()
                    ftd_csv_writer.writerow(header)
                    done_ftd_headers = True

                if done_ftd_headers:
                    ftd_csv_writer.writerow(change.values())

            if "ASA" in change["changedEntity"]["hostToolTip"]["osName"].upper():

                if not done_asa_headers:
                    header = change.keys()
                    asa_csv_writer.writerow(header)
                    done_asa_headers = True

                if done_asa_headers:
                    asa_csv_writer.writerow(change.values())

    ftd_data_file.close()
    asa_data_file.close()


if __name__ == "__main__":
    main()