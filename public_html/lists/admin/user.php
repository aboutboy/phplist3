<?php

require_once dirname(__FILE__).'/accesscheck.php';
require_once dirname(__FILE__).'/date.php';

if (!defined('PHPLISTINIT')) {
    exit;
}

$id = sprintf('%d', isset($_GET['id']) ? $_GET['id'] : 0);
$delete = sprintf('%d', isset($_GET['delete']) ? $_GET['delete'] : 0);
$start = isset($_GET['start']) ? sprintf('%d', $_GET['start']) : 0;
if (isset($_GET['findby'])) {
    $findby = $_GET['findby'];
} else {
    $findby = '';
}
if (isset($_GET['find'])) { //# those notices are driving me nuts ...
    $find = $_GET['find']; //# I guess we should check on validity of it as well
} else {
    $find = '';
}

$date = new Date();
if (isset($_GET['find'])) {
    $find = preg_replace('/\W/', '', $_GET['find']);
} else {
    $find = '';
}
if (isset($_GET['findby'])) {
    $findby = preg_replace('/\W/', '', $_GET['findby']);
} else {
    $findby = '';
}

$access = accessLevel('user');
switch ($access) {
    case 'owner':
        $subselect = sprintf(' and %s.owner = %d', $tables['list'], $_SESSION['logindetails']['id']);
        $subselect_where = sprintf(' where %s.owner = %d', $tables['list'], $_SESSION['logindetails']['id']);
        break;
    case 'all':
        $subselect = '';
        $subselect_where = '';
        break;
    case 'view':
        $subselect = '';
        if (count($_POST)) {
            echo Error(s('You only have privileges to view this page, not change any of the information'));

            return;
        }
        break;
    case 'none':
    default:
        $subselect = ' and '.$tables['list'].'.id = 0';
        $subselect_where = ' where '.$tables['list'].'.owner = 0';
        break;
}

require dirname(__FILE__).'/structure.php';

$struct = $DBstruct['user'];
$feedback = '';

if (!empty($_POST['change']) && ($access == 'owner' || $access == 'all')) {
    if (!verifyToken()) {
        echo Error($GLOBALS['I18N']->get('Invalid security token, please reload the page and try again'));

        return;
    }
    if (isset($_POST['email']) && !empty($_POST['email'])) {
        //# let's not validate here, an admin can add anything as an email, if they like, well, except for HTML
        $email = trim(strip_tags($_POST['email']));
    } else {
        $email = '';
    }

    // validate that an email address has been entered
    if ($email == '') {
        $_SESSION['action_result'] = s('email address cannot be empty');
        $location = $id == 0 ? 'user' : "user&id=$id";
        Redirect($location);
    }

    if ($id == 0) {
        $id = addNewUser($email);
        Redirect("user&id=$id");
    }

    // validate that the email address does not already exist
    $queryResult = Sql_Fetch_Row_Query(sprintf("select 1 from %s where email = '%s' and id != %d", $tables['user'], sql_escape($email), $id));

    if ($queryResult) {
        $_SESSION['action_result'] = s('email address %s already exists', $email);
        Redirect("user&id=$id");
    }

    /************ BEGIN <whitout_error IF block>  (end in line 264) **********************/
    // read the current values to compare changes
    $old_data = Sql_Fetch_Array_Query(sprintf('select * from %s where id = %d', $tables['user'], $id));
    $old_data = array_merge($old_data, getUserAttributeValues('', $id));

    // and membership of lists
    $old_listmembership = array();
    $req = Sql_Query("select * from {$tables['listuser']} where userid = $id");
    while ($row = Sql_Fetch_Array($req)) {
        $old_listmembership[$row['listid']] = listName($row['listid']);
    }

    while (list($key, $val) = each($struct)) {
        if (is_array($val)) {
            if (isset($val[1]) && strpos($val[1], ':')) {
                list($a, $b) = explode(':', $val[1]);
            } else {
                $a = $b = '';
            }
            if (strpos($a, 'sys') === false && $val[1]) {
                if ($key == 'password') {
                    if (!empty($_POST[$key])) {
                        Sql_Query("update {$tables['user']} set $key = \"".encryptPass($_POST[$key])."\" where id = $id");
                    }
                } else {
                    if ($key != 'password' || !empty($_POST[$key])) {
                        if ($key == 'password') {
                            $_POST[$key] = hash('sha256', $_POST[$key]);
                        }

                        Sql_Query("update {$tables['user']} set $key = \"".sql_escape($_POST[$key])."\" where id = $id");
                    }
                }
            } elseif ((!$require_login || ($require_login && isSuperUser())) && $key == 'confirmed') {
                Sql_Query("update {$tables['user']} set $key = \"".sql_escape($_POST[$key])."\" where id = $id");
            }
        }
    }

    if (!empty($_FILES) && is_array($_FILES)) { //# only avatars are files
        foreach ($_FILES['attribute']['name'] as $key => $val) {
            if (!empty($_FILES['attribute']['name'][$key])) {
                $tmpnam = $_FILES['attribute']['tmp_name'][$key];
                $size = $_FILES['attribute']['size'][$key];

                if ($size < MAX_AVATAR_SIZE) {
                    $avatar = file_get_contents($tmpnam);
                    Sql_Query(sprintf('replace into %s (userid,attributeid,value)
             values(%d,%d,"%s")', $tables['user_attribute'], $id, $key, base64_encode($avatar)));
                } elseif ($size) {
                    echo Error($GLOBALS['I18N']->get('Uploaded avatar file too big'));
                }
            }
        }
    }

    if (isset($_POST['attribute']) && is_array($_POST['attribute'])) {
        foreach ($_POST['attribute'] as $key => $val) {
            Sql_Query(sprintf('replace into %s (userid,attributeid,value)
       values(%d,%d,"%s")', $tables['user_attribute'], $id, $key, sql_escape($val)));
        }
    }

    if (isset($_POST['dateattribute']) && is_array($_POST['dateattribute'])) {
        foreach ($_POST['dateattribute'] as $attid => $fields) {
            if (isset($fields['novalue'])) {
                $value = '';
            } else {
                $value = sprintf('%04d-%02d-%02d', $fields['year'], $fields['month'], $fields['day']);
            }
            Sql_Query(sprintf('replace into %s (userid,attributeid,value)
       values(%d,%d,"%s")', $tables['user_attribute'], $id, $attid, $value));
        }
    }

    if (isset($_POST['cbattribute']) && is_array($_POST['cbattribute'])) {
        while (list($key, $val) = each($_POST['cbattribute'])) {
            if (isset($_POST['attribute'][$key]) && $_POST['attribute'][$key] == 'on') {
                Sql_Query(sprintf('replace into %s (userid,attributeid,value)
         values(%d,%d,"on")', $tables['user_attribute'], $id, $key));
            } else {
                Sql_Query(sprintf('replace into %s (userid,attributeid,value)
         values(%d,%d,"")', $tables['user_attribute'], $id, $key));
            }
        }
    }

    if (isset($_POST['cbgroup']) && is_array($_POST['cbgroup'])) {
        while (list($key, $val) = each($_POST['cbgroup'])) {
            $field = 'cbgroup'.$val;
            if (isset($_POST[$field]) && is_array($_POST[$field])) {
                $newval = array();
                foreach ($_POST[$field] as $fieldval) {
                    array_push($newval, sprintf('%0'.$checkboxgroup_storesize.'d', $fieldval));
                }
                $value = implode(',', $newval);
            } else {
                $value = '';
            }
            Sql_Query(sprintf('replace into %s (userid,attributeid,value)
       values(%d,%d,"%s")', $tables['user_attribute'], $id, $val, $value));
        }
    }

    $new_lists = array_values($_POST['subscribe']);
    $new_subscriptions = array();
    array_shift($new_lists); // remove dummy
    foreach ($new_lists as $list) {
        $listID = sprintf('%d', $list);
        $new_subscriptions[$listID] = listName($listID);
    }

    $subscribed_to = array_diff_assoc($new_subscriptions, $old_listmembership);
    $unsubscribed_from = array_diff_assoc($old_listmembership, $new_subscriptions);

    // submitting page now saves everything, so check is not necessary
    if ($subselect == '') {
        foreach ($unsubscribed_from as $listId => $listName) {
            Sql_Query(sprintf('delete from %s where userid = %d and listid = %d', $tables['listuser'], $id,
                $listId));
            $feedback .= '<br/>'.sprintf(s('Subscriber removed from list %s'), $listName);
        }
    } elseif (count($unsubscribed_from)) {
        // only unsubscribe from the lists of this admin
        $req = Sql_Query("select id,name from {$tables['list']} $subselect_where and id in (".implode(',',
                array_keys($unsubscribed_from)).')');
        while ($row = Sql_Fetch_Row($req)) {
            Sql_Query("delete from {$tables['listuser']} where userid = $id and listid = $row[0]");
            $feedback .= '<br/>'.sprintf(s('Subscriber removed from list %s'), $row[1]);
        }
    }
    if (count($subscribed_to)) {
        foreach ($subscribed_to as $listID => $listName) {
            Sql_Query("insert into {$tables['listuser']} (userid,listid,entered,modified) values($id,$listID,now(),now())");
            $feedback .= '<br/>'.sprintf($GLOBALS['I18N']->get('Subscriber added to list %s'), $listName);
        }
        $feedback .= '<br/>';
    }
    $history_entry = '';
    $current_data = Sql_Fetch_Array_Query(sprintf('select * from %s where id = %d', $tables['user'], $id));
    $current_data = array_merge($current_data, getUserAttributeValues('', $id));

    foreach ($current_data as $key => $val) {
        if (!is_numeric($key)) {
            if (isset($old_data[$key]) && $old_data[$key] != $val && $key != 'modified') {
                if ($old_data[$key] == '') {
                    $old_data[$key] = s('(no data)');
                }
                $history_entry .= "$key = $val\n".s('changed from')." $old_data[$key]\n";
            }
        }
    }
    if (!$history_entry) {
        $history_entry = "\n".s('No data changed')."\n";
    }

    foreach ($subscribed_to as $key => $desc) {
        $history_entry .= s('Subscribed to %s', $desc)."\n";
    }
    foreach ($unsubscribed_from as $key => $desc) {
        $history_entry .= s('Unsubscribed from %s', $desc)."\n";
    }

    addUserHistory($email, s('Update by %s', adminName($_SESSION['logindetails']['id'])), $history_entry);
    $_SESSION['action_result'] = s('Changes saved').$feedback;
    Redirect("user&id=$id");
    /************ END <whitout_error IF block>  (start in line 71) **********************/
}

if (isset($delete) && $delete && $access != 'view') {
    verifyCsrfGetToken();
    // delete the index in delete
    $_SESSION['action_result'] = s('Deleting').' '.s('Subscriber').' '.s('ID')." $delete ..\n";
    if ($require_login && !isSuperUser()) {
        // If the user does not permission to permanently delete, delete
        // subscriptoins instead

        // Get all lists subscriber is a member of
        $lists = Sql_query("
            SELECT 
                listid 
            FROM 
                {$tables['listuser']},{$tables['list']} 
            WHERE 
                userid = ".$delete." 
                AND $tables[listuser].listid = $tables[list].id 
                $subselect 
        ");
        while ($lst = Sql_fetch_array($lists)) {
            Sql_query("
                DELETE FROM 
                    {$tables['listuser']} 
                WHERE 
                    userid = $delete 
                    AND listid = $lst[0]
            ");
        }
    } else {
        // permanently delete subscriber
        deleteUser($delete);
    }
    $_SESSION['action_result'] .= s('Done')."\n";
    Redirect('user');
}

/********* NORMAL FORM DISPLAY ***********/
$membership = '';
$subscribed = array();
if ($id) {
    $result = Sql_query(sprintf('select * from %s where id = %d', $tables['user'], $id));

    if (!Sql_Affected_Rows()) {
        Fatal_Error(s('No such subscriber'));

        return;
    }

    $user = sql_fetch_array($result);
    $lists = Sql_query("SELECT listid,name FROM {$tables['listuser']},{$tables['list']} where userid = ".$user['id']." and $tables[listuser].listid = $tables[list].id $subselect ");

    while ($lst = Sql_fetch_array($lists)) {
        $membership .= '<li>'.PageLink2('editlist', cleanListName($lst['name']), 'id='.$lst['listid']).'</li>';
        array_push($subscribed, $lst['listid']);
    }

    if (!$membership) {
        $membership = $GLOBALS['I18N']->get('No Lists');
    }

    echo '<div class="actions">';

    if (!empty($GLOBALS['config']['plugins']) && is_array($GLOBALS['config']['plugins'])) {
        foreach ($GLOBALS['config']['plugins'] as $pluginName => $plugin) {
            echo $plugin->userpageLink($id);
        }
    }

    if ($access == 'all') {
        $delete = new ConfirmButton(
            htmlspecialchars(s('Are you sure you want to remove this subscriber from the system.')),
            PageURL2("user&delete=$id".addCsrfGetToken(), 'button', s('remove subscriber')),
            s('remove subscriber'));
        echo $delete->show();
    }

    echo '</div>';
} else {
    if (!empty($_POST['subscribe'])) {
        foreach ($_POST['subscribe'] as $idx => $listid) {
            array_push($subscribed, $listid);
        }
    }

    $id = 0;
    echo '<h3>'.s('Add a new subscriber').'</h3>';
    if (empty($_POST['email'])) {
        echo formStart();
        echo s('Email address').': '.'<input type="text" name="email" value="" />';
        echo '<input type="submit" name="change" value="'.s('Continue').'">';
        echo '</form>';

        return;
    }
}

echo formStart('enctype="multipart/form-data"');
if (empty($list)) {
    $list = '';
}
echo '<input type="hidden" name="list" value="'.$list.'" /><input type="hidden" name="id" value="'.$id.'" />';
if (empty($returnpage)) {
    $returnpage = '';
}
if (empty($returnoption)) {
    $returnoption = '';
}
echo '<input type="hidden" name="returnpage" value="'.$returnpage.'" /><input type="hidden" name="returnoption" value="'.$returnoption.'" />';

reset($struct);

$userdetailsHTML = $mailinglistsHTML = '';

if (isBlackListed($user['email'])) {
    $userdetailsHTML .= '<h3 class="alert-info">'.s('Subscriber is blacklisted. No emails will be sent to this email address.').'</h3>';
}

$userdetailsHTML .= '<table class="userAdd" border="1">';

while (list($key, $val) = each($struct)) {
    @list($a, $b) = explode(':', $val[1]);

    if (!isset($user[$key])) {
        $user[$key] = '';
    }

    if ($key == 'confirmed') {
        if (!$require_login || ($require_login && isSuperUser())) {
            $userdetailsHTML .= sprintf('<tr><td class="dataname">%s (1/0)</td><td><input type="text" name="%s" value="%s" size="5" /></td></tr>'."\n",
                $GLOBALS['I18N']->get($b), $key, htmlspecialchars(stripslashes($user[$key])));
        } else {
            $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td>%s</td></tr>', $b,
                stripslashes($user[$key]));
        }
    } elseif ($key == 'password') {
        $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td><input type="text" name="%s" value="%s" size="30" /></td></tr>'."\n",
            $val[1], $key, '');
    } elseif ($key == 'blacklisted') {
        $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td>%s', $GLOBALS['I18N']->get($b),
            $user[$key] || isBlackListed($user['email']) ? s('Yes') : s('No'));

        if (!($user[$key] || isBlackListed($user['email']))) {
            $userdetailsHTML .= '<span class="fright button">'.PageLinkAjax('user&blacklist=1&id='.$user['id'],
                    s('Add to blacklist')).'</span>';
        } elseif (UNBLACKLIST_IN_PROFILE) {
            $userdetailsHTML .= '<span class="fright button">'.PageLinkAjax('user&unblacklist=1&id='.$user['id'],
                    s('Remove from blacklist')).'</span>';
        }
        $userdetailsHTML .= '</td></tr>';
    } else {
        if (!strpos($key, '_')) {
            if (strpos($a, 'sys') !== false) {
                $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td>%s</td></tr>',
                    $GLOBALS['I18N']->get($b), stripslashes($user[$key]));
            } elseif ($val[1]) {
                $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td><input type="text" name="%s" value="%s" size="30" /></td></tr>'."\n",
                    $GLOBALS['I18N']->get($val[1]), $key, htmlspecialchars(stripslashes($user[$key])));
            }
        }
    }
}

if (empty($GLOBALS['config']['hide_user_attributes']) && !defined('HIDE_USER_ATTRIBUTES')) {
    $res = Sql_Query("select * from $tables[attribute] order by listorder");

    while ($row = Sql_fetch_array($res)) {
        if (!empty($id)) {
            $val_req = Sql_Fetch_Row_Query("select value from $tables[user_attribute] where userid = $id and attributeid = $row[id]");
            $row['value'] = $val_req[0];
        } elseif (!empty($_POST['attribute'][$row['id']])) {
            $row['value'] = $_POST['attribute'][$row['id']];
        } else {
            $row['value'] = '';
        }

        if ($row['type'] == 'date') {
            $namePrefix = sprintf('dateattribute[%d]', $row['id']);
            $novalue = trim($row['value']) == '' ? 'checked' : '';
            $userdetailsHTML .= sprintf(
                '<tr><td class="dataname">%s<!--%s--></td>
        <td>%s&nbsp; Not set: <input type="checkbox" name="%s[novalue]" %s /></td></tr>' ."\n",
                stripslashes($row['name']),
                $row['value'],
                $date->showInput($namePrefix, '', $row['value']),
                $namePrefix,
                $novalue
            );
        } elseif ($row['type'] == 'checkbox') {
            $checked = $row['value'] == 'on' ? 'checked="checked"' : '';
            $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td><input class="attributeinput" type="hidden" name="cbattribute[%d]" value="%d" />
                        <input class="attributeinput" type="checkbox" name="attribute[%d]" value="on" %s />
              </td></tr>' ."\n", stripslashes($row['name']), $row['id'], $row['id'], $row['id'], $checked);
        } elseif ($row['type'] == 'checkboxgroup') {
            $userdetailsHTML .= sprintf('
           <tr><td valign="top" class="dataname">%s</td><td>%s</td>
           </tr>', stripslashes($row['name']), UserAttributeValueCbGroup($id, $row['id']));
        } elseif ($row['type'] == 'textarea') {
            $userdetailsHTML .= sprintf('
           <tr><td valign="top" class="dataname">%s</td><td><textarea name="attribute[%d]" rows="10" cols="40" class="wrap virtual">%s</textarea></td>
           </tr>', stripslashes($row['name']), $row['id'], htmlspecialchars(stripslashes($row['value'])));
        } elseif ($row['type'] == 'avatar') {
            $userdetailsHTML .= sprintf('<tr><td valign="top" class="dataname">%s</td><td>',
                stripslashes($row['name']));
            if ($row['value']) {
                $userdetailsHTML .= sprintf('<img src="./?page=avatar&amp;user=%d&amp;avatar=%s" /><br/>', $id,
                    $row['id']);
            }
            $userdetailsHTML .= sprintf('<input type="file" name="attribute[%d]" /><br/>MAX: %d Kbytes</td>
           </tr>', $row['id'], MAX_AVATAR_SIZE / 1024);
        } else {
            if ($row['type'] != 'textline' && $row['type'] != 'hidden') {
                $userdetailsHTML .= sprintf("<tr><td class='dataname'>%s</td><td>%s</td></tr>\n",
                    stripslashes($row['name']), UserAttributeValueSelect($id, $row['id']));
            } else {
                $userdetailsHTML .= sprintf('<tr><td class="dataname">%s</td><td><input class="attributeinput" type="text" name="attribute[%d]" value="%s" size="30" /></td></tr>'."\n",
                    $row['name'], $row['id'], htmlspecialchars(stripslashes($row['value'])));
            }
        }
    }
}

if ($access != 'view') {
    $userdetailsHTML .= '<tr><td colspan="2" class="bgwhite"><input class="submit" type="submit" name="change" value="'.$GLOBALS['I18N']->get('Save Changes').'" /></td></tr>';
}
$userdetailsHTML .= '</table>';

$mailinglistsHTML .= '<h3>'.$GLOBALS['I18N']->get('Mailinglist membership').':</h3>';
// a dummy entry, to make the array show up in POST even if all checkboxes are unchecked
$mailinglistsHTML .= '<input type="hidden" name="subscribe[]" value="-1" />';
$mailinglistsHTML .= '<table class="userListing" border="1"><tr>';
$req = Sql_Query("select * from {$tables['list']} $subselect_where order by listorder,name");
$c = 0;
while ($row = Sql_Fetch_Array($req)) {
    ++$c;
    if ($c % 1 == 0) {
        $mailinglistsHTML .= '</tr><tr>';
    }
    if (in_array($row['id'], $subscribed)) {
        $bgcol = '#F7E7C2';
        $subs = 'checked="checked"';
    } else {
        $bgcol = '#ffffff';
        $subs = '';
    }
    $mailinglistsHTML .= sprintf('<td class="tdcheck" bgcolor="%s"><input type="checkbox" name="subscribe[]" value="%d" %s /> %s</td>',
        $bgcol, $row['id'], $subs, stripslashes(cleanListName($row['name'])));
}
$mailinglistsHTML .= '</tr>';
if ($access != 'view') {
    $mailinglistsHTML .= '<tr><td class="bgwhite"><input class="submit" type="submit" name="change" value="'.$GLOBALS['I18N']->get('Save Changes').'" /></td></tr>';
}

$mailinglistsHTML .= '</table>';

$bouncels = new WebblerListing(s('Bounces'));
$bouncels->setElementHeading('Bounce ID');
$bouncelist = '';
$bounces = array();
// check for bounces
$req = Sql_Query(sprintf('
select 
    message_bounce.id
    , message_bounce.message
    , time
    , bounce
    , date_format(time,"%%e %%b %%Y %%T") as ftime
from 
    %s as message_bounce
where 
    user = %d', $tables['user_message_bounce'], $user['id']));

if (Sql_Affected_Rows()) {
    while ($row = Sql_Fetch_Array($req)) {
        $messagedata = loadMessageData($row['message']);
        $bouncels->addElement($row['bounce'],
            PageURL2('bounce', s('view'), 'id='.$row['bounce']));
        $bouncels->addColumn($row['bounce'], s('Campaign title'), stripslashes($messagedata['campaigntitle']));
        $bouncels->addColumn($row['bounce'], s('time'), $row['ftime']);
        $bounces[$row['message']] = $row['ftime'];
    }
}

$ls = new WebblerListing(s('Campaigns'));
if (Sql_Table_Exists($tables['usermessage'])) {
    $msgs = Sql_Query(sprintf('select messageid,entered,viewed,(viewed = 0 or viewed is null) as notviewed,
    abs(unix_timestamp(entered) - unix_timestamp(viewed)) as responsetime from %s where userid = %d and status = "sent" order by entered desc',
        $tables['usermessage'], $user['id']));
    $num = Sql_Affected_Rows();
} else {
    $num = 0;
}
printf('%d '.s('messages sent to this user').'<br/>', $num);
if ($num) {
    $resptime = 0;
    $totalresp = 0;
    $ls->setElementHeading(s('Campaign Id'));

    while ($msg = Sql_Fetch_Array($msgs)) {
        $ls->addElement($msg['messageid'],
            PageURL2('message', s('view'), 'id='.$msg['messageid']));
        if (defined('CLICKTRACK') && CLICKTRACK) {
            $clicksreq = Sql_Fetch_Row_Query(sprintf('select sum(clicked) as numclicks from %s where userid = %s and messageid = %s',
                $GLOBALS['tables']['linktrack_uml_click'], $user['id'], $msg['messageid']));
            $clicks = sprintf('%d', $clicksreq[0]);
            if ($clicks) {
                $ls->addColumn($msg['messageid'], s('clicks'),
                    PageLink2('userclicks&amp;userid='.$user['id'].'&amp;msgid='.$msg['messageid'], $clicks));
            } else {
                $ls->addColumn($msg['messageid'], s('clicks'), 0);
            }
        }

        $ls->addColumn($msg['messageid'], s('sent'), formatDateTime($msg['entered'], 1));
        if (!$msg['notviewed']) {
            $ls->addColumn($msg['messageid'], s('viewed'), formatDateTime($msg['viewed'], 1));
            $ls->addColumn($msg['messageid'], s('Response time'), secs2time($msg['responsetime']));
            $resptime += $msg['responsetime'];
            $totalresp += 1;
        }
        if (!empty($bounces[$msg['messageid']])) {
            $ls->addColumn($msg['messageid'], s('bounce'), $bounces[$msg['messageid']]);
        }
    }
    if ($totalresp) {
        $avgresp = sprintf('%d', ($resptime / $totalresp));
        $ls->addElement('<strong>'.s('Average response time: ').'</strong>'.secs2time($avgresp));
    }
}

echo '<div class="tabbed">';
echo '<ul>';
echo '<li><a href="#details">'.ucfirst($GLOBALS['I18N']->get('Details')).'</a></li>';
echo '<li><a href="#lists">'.ucfirst($GLOBALS['I18N']->get('Lists')).'</a></li>';
echo '<li><a href="#messages">'.ucfirst(s('Campaigns')).'</a></li>';
if (count($bounces)) {
    echo '<li><a href="#bounces">'.ucfirst(s('Bounces')).'</a></li>';
}
echo '<li><a href="#subscription">'.ucfirst(s('Subscription')).'</a></li>';

echo '</ul>';

$p = new UIPanel('', $userdetailsHTML);
echo '<div id="details">'.$p->display().'</div>';

$p = new UIPanel('', $mailinglistsHTML);
echo '<div id="lists">'.$p->display().'</div>';
echo '<div id="messages">';
echo $ls->display();
echo '</div>';
echo '<div id="bounces">';
echo $bouncels->display();
echo '</div>';
echo '<div id="subscription">';
if (isBlackListed($user['email'])) {
    echo '<h3>'.s('subscriber is blacklisted since').' ';
    $blacklist_info = Sql_Fetch_Array_Query(sprintf('select * from %s where email = "%s"',
        $tables['user_blacklist'], $user['email']));
    echo formatDateTime($blacklist_info['added']).'</h3><br/>';
    echo '';

    $isSpamReport = false;
    $Subscriptionls = new WebblerListing(s('Blacklist info'));
    $req = Sql_Query(sprintf('select * from %s where email = "%s"',
        $tables['user_blacklist_data'], $user['email']));
    while ($row = Sql_Fetch_Array($req)) {
        $Subscriptionls->addElement(s($row['name']));
        $isSpamReport = $isSpamReport || $row['data'] == 'blacklisted due to spam complaints';
        $Subscriptionls->addColumn(s($row['name']), s('value'), stripslashes($row['data']));
    }
    $Subscriptionls->addElement('<!-- remove -->');
    if (!$isSpamReport) {
        $button = new ConfirmButton(
            htmlspecialchars(s('are you sure you want to delete this subscriber from the blacklist')).'?\\n'.htmlspecialchars(s('it should only be done with explicit permission from this subscriber')),
            PageURL2("userhistory&unblacklist={$user['id']}&id={$user['id']}", 'button',
                s('remove subscriber from blacklist')),
            s('remove subscriber from blacklist'));

        $Subscriptionls->addRow('<!-- remove -->', s('remove'), $button->show());
    } else {
        $Subscriptionls->addRow('<!-- remove -->', s('remove'),
            s('For this subscriber to be removed from the blacklist, you need to ask them to re-subscribe using the phpList subscribe page'));
    }
    echo $Subscriptionls->display();
}

$Subscriptionls = new WebblerListing(s('Subscription History'));
$Subscriptionls->setElementHeading(s('Event'));
$req = Sql_Query(sprintf('select * from %s where userid = %d order by id desc', $tables['user_history'], $user['id']));
if (!Sql_Affected_Rows()) {
    echo s('no details found');
}
while ($row = Sql_Fetch_Array($req)) {
    $Subscriptionls->addElement($row['id']);
    $Subscriptionls->setClass($row['id'], 'row1');
    $Subscriptionls->addColumn($row['id'], s('ip'), $row['ip']);
    $Subscriptionls->addColumn($row['id'], s('date'), formatDateTime($row['date']));
    $Subscriptionls->addColumn($row['id'], s('summary'), $row['summary']);
    $Subscriptionls->addRow(
        $row['id']
        , "<div class='gray'><strong>".s('detail').'</strong></div>'
        , "<div class='tleft'>".
        nl2br(
            htmlspecialchars(
                $row['detail']
            )
        ).'</div>'
    );
    // nl2br inserts leading <br/> elements and unnecessary whitespace; preg_replace removes this
    $Subscriptionls->addRow(
        $row['id']
        , "<div class='gray'><strong>".s('info').'</strong></div>'
        , "<div class='tleft'>".
        preg_replace(
            "|^(?:<br />[\n\r]+)*(.*?)(?:<br />[\n\r]+)*$|s"
            , '$1'
            , nl2br(
                htmlspecialchars_decode(
                    $row['systeminfo']
                )
            )
        ).'</div>'
    );
}

echo $Subscriptionls->display();
echo '</div>';


echo '</div>'; //# end of tabbed

echo '</form>';
